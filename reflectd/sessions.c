#include <assert.h>
#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "hash.h"
#include "queue.h"
#include "sessions.h"
#include "util.h"


uint64_t
adjust_seq(uint32_t seq_lower, uint64_t next_seq)
{
    int32_t offset;

    offset = seq_lower - (next_seq & 0xffffffff);
    return next_seq + offset;
}

struct context *
context_init(struct context *ctx, size_t max_connections)
{
    ctx->lookup = calloc(max_connections, sizeof(*ctx->lookup));
    ctx->sessions = calloc(max_connections, sizeof(*ctx->sessions));

    if (ctx->lookup == NULL || ctx->sessions == NULL) {
        free(ctx->lookup);
        free(ctx->sessions);
        return NULL;
    } else
        return ctx;
}

void
context_teardown(struct context *ctx)
{
    size_t i;

    for (i = 0; i < ctx->max_connections; i++) {
        session_release(ctx, &ctx->sessions[i]);
    }

    /* XXX: ctx->local_ips and ctx->listen_ips must be freed by caller */

    free(ctx->lookup);
    free(ctx->sessions);
}

static inline uint32_t
context_hash_session(uint32_t source_ip, uint16_t source_port)
{
    uint8_t key[sizeof(source_ip) + sizeof(source_port)];

    memcpy(key, &source_ip, sizeof(source_ip));
    memcpy(key + sizeof(source_ip), &source_port, sizeof(source_port));
    return crap8_hash(key, sizeof(key));
}

static struct session *
context_find_session(struct context *ctx, uint32_t source_ip,
                     uint16_t source_port)
{
    struct session *session;
    uint32_t idx;

    idx = context_hash_session(source_ip, source_port) % ctx->max_connections;
    session = ctx->lookup[idx];

    for (; session != NULL; session = session->next) {
        if (session->source_ip == source_ip &&
            session->source_port == source_port)
            return session;
    }

    return NULL;
}

static void
context_add_session(struct context *ctx, struct session *session)
{
    uint32_t idx;

    idx = (context_hash_session(session->source_ip, session->source_port) %
           ctx->max_connections);
    session->next = ctx->lookup[idx];
    ctx->lookup[idx] = session;
}

static void
context_remove_session(struct context *ctx, struct session *session)
{
    struct session *cursor, **slot;
    uint32_t idx;

    idx = (context_hash_session(session->source_ip, session->source_port) %
           ctx->max_connections);
    slot = &ctx->lookup[idx];

    for (cursor = ctx->lookup[idx]; cursor != NULL; cursor = cursor->next) {
        if (cursor->source_ip == session->source_ip &&
            cursor->source_port == session->source_port) {
            *slot = cursor->next;
        }
        slot = &cursor->next;
    }
}

void
context_dump(struct context *ctx)
{
    struct session *session;
    struct segment *segment;
    size_t i;

    for (i = 0; i < ctx->max_connections; i++) {
        session = &ctx->sessions[i];

        if (!session->is_used)
            continue;

        segment = TAILQ_FIRST(&session->send_queue);
        if (segment == NULL)
            segment = TAILQ_FIRST(&session->recv_queue);

        if (segment == NULL)
            printf("%04x:%d next_seq=%llx, no queued segment\n",
                   session->source_ip, session->source_port,
                   (long long)session->next_seq);
        else
            printf("%04x:%d next_seq=%llx, queued seq=%llx\n",
                   session->source_ip, session->source_port,
                   (long long)session->next_seq,
                   (long long)segment->seq);
    }
}

struct segment *
segment_create(size_t data_len)
{
    return malloc(offsetof(struct segment, bytes) + data_len);
}

void
segment_destroy(struct segment *segment)
{
    free(segment);
}

static void
segment_fixup_overlap(struct segment *segment, uint64_t next_seq)
{
    size_t offset;

    if (segment == NULL)
        return;

    if (segment->seq < next_seq) {
        offset = next_seq - segment->seq;
        segment->dataptr += offset;
        segment->seq += offset;
        segment->length -= offset;
    }
}

struct session *
session_allocate(struct context *ctx, uint32_t source_ip,
                 uint16_t source_port, uint32_t next_seq)
{
    struct session *session;
    size_t i;
    time_t now = time(NULL);

    for (i = 0; i < ctx->max_connections; i++) {
        session = &ctx->sessions[i];
        if (!session->is_used ||
            session->latest_timestamp + ctx->timeout_seconds < now)
            break;
    }

    if (i >= ctx->max_connections)
        return NULL;

    if (session->is_used)
        session_release(ctx, session);

    TAILQ_INIT(&session->recv_queue);
    TAILQ_INIT(&session->send_queue);

    session->next_seq = next_seq;
    session->latest_timestamp = time(NULL);
    session->source_ip = source_ip;
    session->source_port = source_port;
    session->fd = -1;
    session->is_used = 1;

    context_add_session(ctx, session);

    return session;
}

struct session *
session_find(struct context *ctx, uint32_t source_ip,
             uint16_t source_port)
{
    return context_find_session(ctx, source_ip, source_port);
}

void
session_release(struct context *ctx, struct session *session)
{
    struct segment *segment;

    if (session == NULL || !session->is_used)
        return;

    if (session->fd >= 0)
        close(session->fd);

    while ((segment = TAILQ_FIRST(&session->recv_queue)) != NULL) {
        TAILQ_REMOVE(&session->recv_queue, segment, segments);
        segment_destroy(segment);
    }

    while ((segment = TAILQ_FIRST(&session->send_queue)) != NULL) {
        TAILQ_REMOVE(&session->send_queue, segment, segments);
        segment_destroy(segment);
    }

    context_remove_session(ctx, session);
    session->is_used = 0;
}

void
session_insert(struct context *ctx, struct session *session,
               struct segment *segment)
{
    struct segment *prev, *cur;
    int64_t offset;

    offset = segment->seq - session->next_seq;

    /* Discard segments below the window. For FIN or RST we may have
       segment->length == 0, so both checks are required. */
    if (segment->seq < session->next_seq &&
        segment->seq + segment->length <= session->next_seq) {
        offset = -offset - segment->length;
        if (offset > ctx->window_size_bytes)
            log_msg("dropped segment %lld bytes below next expected seq",
                    (long long)offset);
        goto fail;
    }

    if (offset > ctx->window_size_bytes) {
        log_msg("dropped segment %lld bytes above next expected seq",
                (long long)offset);
        goto fail;
    }

    cur = TAILQ_LAST(&session->recv_queue, recv_head);

    while (cur != NULL && cur->seq >= segment->seq) {
        prev = TAILQ_PREV(cur, recv_head, segments);

        /* Delete any segments contained within this segment. */
        if (cur->seq < segment->seq + segment->length &&
            cur->seq + cur->length <= segment->seq + segment->length) {
            TAILQ_REMOVE(&session->recv_queue, cur, segments);
            segment_destroy(cur);
        }

        cur = prev;
    }

    /* Fix up any overlapping segments. */
    if (cur != NULL) {
        segment_fixup_overlap(segment, cur->seq + cur->length);
        TAILQ_INSERT_AFTER(&session->recv_queue, cur, segment, segments);
    } else {
        segment_fixup_overlap(segment, session->next_seq);
        TAILQ_INSERT_HEAD(&session->recv_queue, segment, segments);
    }

    segment_fixup_overlap(TAILQ_NEXT(segment, segments),
                          segment->seq + segment->length);

    /* Move all contiguous segments to the send queue. */
    while ((cur = TAILQ_FIRST(&session->recv_queue)) != NULL &&
            cur->seq == session->next_seq) {
        TAILQ_REMOVE(&session->recv_queue, cur, segments);
        TAILQ_INSERT_TAIL(&session->send_queue, cur, segments);

        /* The client can reuse the port once the other end knows the connection
           is closed; remove the session from the lookup ctx. */
        if (cur->fin || cur->rst)
            context_remove_session(ctx, session);

        session->next_seq += cur->length;
    }

    session->latest_timestamp = time(NULL);
    return;

fail:
    segment_destroy(segment);
}

struct segment *
session_peek(struct session *session)
{
    return TAILQ_FIRST(&session->send_queue);
}

void
session_pop(struct session *session)
{
    struct segment *segment = TAILQ_FIRST(&session->send_queue);
    TAILQ_REMOVE(&session->send_queue, segment, segments);
    segment_destroy(segment);
}
