#include <assert.h>
#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "definitions.h"
#include "hash.h"
#include "queue.h"
#include "sessions.h"


uint64_t
adjust_seq(uint32_t seq_lower, uint64_t next_seq)
{
    uint64_t seq;
    uint32_t offset;

    // TODO: Handle packets that overlap the next expected sequence number?
    //             Could hypothetically happen with variable path MTU and
    //             retransmission.
    offset = seq_lower - (next_seq & 0xffffffff);

    /* If the offset is outside the receive window, discard the segment. */
    if (offset >= MAX_WINDOW_BYTES)
        return SEQ_INVALID;

    seq = seq_lower | (next_seq & 0xffffffff00000000);
    if (seq < next_seq)
        seq += 0x100000000;

    return seq;
}

struct sessiontable *
sessiontable_create(void)
{
    struct sessiontable *table;

    table = calloc(1, sizeof(struct sessiontable));

    if (table == NULL) {
        warnx("failed to allocate table");
        return NULL;
    }

    return table;
}

void
sessiontable_destroy(struct sessiontable *table)
{
    size_t i;

    for (i = 0; i < ARRAYSIZE(table->sessions); i++) {
        session_release(table, &table->sessions[i]);
    }

    free(table);
}

static inline uint32_t
sessiontable_hash(uint32_t source_ip, uint16_t source_port)
{
    uint8_t key[sizeof(source_ip) + sizeof(source_port)];

    memcpy(key, &source_ip, sizeof(source_ip));
    memcpy(key + sizeof(source_ip), &source_port, sizeof(source_port));
    return crap8_hash(key, sizeof(key));
}

static struct session *
sessiontable_find(struct sessiontable *table, uint32_t source_ip,
                  uint16_t source_port)
{
    struct session *session;
    uint32_t idx;

    idx = sessiontable_hash(source_ip, source_port) % ARRAYSIZE(table->lookup);
    session = table->lookup[idx];

    for (; session != NULL; session = session->next) {
        if (session->source_ip == source_ip &&
            session->source_port == source_port)
            return session;
    }

    return NULL;
}

void
sessiontable_insert(struct sessiontable *table, struct session *session)
{
    uint32_t idx;

    idx = (sessiontable_hash(session->source_ip, session->source_port) %
           ARRAYSIZE(table->lookup));
    session->next = table->lookup[idx];
    table->lookup[idx] = session;
}

void
sessiontable_remove(struct sessiontable *table, struct session *session)
{
    struct session *cursor, **slot;
    uint32_t idx;

    idx = (sessiontable_hash(session->source_ip, session->source_port) %
           ARRAYSIZE(table->lookup));
    slot = &table->lookup[idx];

    for (cursor = table->lookup[idx]; cursor != NULL; cursor = cursor->next) {
        if (cursor->source_ip == session->source_ip &&
            cursor->source_port == session->source_port) {
            *slot = cursor->next;
        }
        slot = &cursor->next;
    }
}

void
sessiontable_dump(struct sessiontable *table)
{
    struct session *session;
    struct segment *segment;
    size_t i;

    for (i = 0; i < MAX_TCP_SESSIONS; i++) {
        session = &table->sessions[i];

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
    return malloc(sizeof(struct segment) + data_len);
}

void
segment_destroy(struct segment *segment)
{
    free(segment);
}

void
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

static inline int
session_is_dead(struct session *session)
{
    return session->latest_timestamp + MAX_TCP_SESSIONS < time(NULL);
}

struct session *
session_allocate(struct sessiontable *table, uint32_t source_ip,
                 uint16_t source_port, uint32_t next_seq)
{
    struct session *session;
    size_t i;

    for (i = 0; i < ARRAYSIZE(table->sessions); i++) {
        if (!table->sessions[i].is_used ||
            session_is_dead(&table->sessions[i]))
            break;
    }

    if (i >= ARRAYSIZE(table->sessions)) {
        warnx("no available session found");
        return NULL;
    }

    session = &table->sessions[i];

    if (session->is_used)
        session_release(table, session);

    TAILQ_INIT(&session->recv_queue);
    TAILQ_INIT(&session->send_queue);

    session->next_seq = next_seq;
    session->latest_timestamp = time(NULL);
    session->source_ip = source_ip;
    session->source_port = source_port;
    session->fd = -1;
    session->is_used = 1;

    sessiontable_insert(table, session);

    return session;
}

struct session *
session_find(struct sessiontable *table, uint32_t source_ip,
             uint16_t source_port)
{
    return sessiontable_find(table, source_ip, source_port);
}

void
session_release(struct sessiontable *table, struct session *session)
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

    sessiontable_remove(table, session);
    session->is_used = 0;
}

void
session_insert(struct sessiontable *table, struct session *session,
               struct segment *segment)
{
    struct segment *prev, *cur;

    if (segment->seq < session->next_seq &&
        segment->seq + segment->length <= session->next_seq) {
        segment_destroy(segment);
        return;
    }

    session->latest_timestamp = time(NULL);
    cur = TAILQ_LAST(&session->recv_queue, recv_head);

    while (cur != NULL && cur->seq >= segment->seq) {
        prev = TAILQ_PREV(cur, recv_head, segments);

        /* Delete any segments contained within this segment. */
        if (cur->seq + cur->length <= segment->seq + segment->length) {
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

        /* The client is can reuse the port once the other end knows the
           connection is closed; remove the session from the lookup table. */
        if (cur->fin || cur->rst)
            sessiontable_remove(table, session);

        session->next_seq += cur->length;
    }
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
