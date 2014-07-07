#include <assert.h>
#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "definitions.h"
#include "hash.h"
#include "segments.h"
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

        segment = segmentq_peek(session->segmentq);

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

    session->segmentq = segmentq_create(MAX_WINDOW_SEGS);

    if (session->segmentq == NULL) {
        warnx("failed to allocate segmentq");
        return NULL;
    }

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

    while ((segment = segmentq_pop(session->segmentq)) != NULL)
        segment_destroy(segment);

    segmentq_destroy(session->segmentq);
    sessiontable_remove(table, session);

    session->is_used = 0;
}

int
session_insert(struct session *session, struct segment *segment)
{
    session->latest_timestamp = time(NULL);
    return segmentq_insert(session->segmentq, segment);
}

struct segment *
session_peek(struct session *session)
{
    struct segment *segment;
    size_t offset;

    /* Remove any segments that fall below the receive window. */
    while ((segment = segmentq_peek(session->segmentq)) != NULL &&
           segment->seq + segment->length <= session->next_seq) {
        segmentq_pop(session->segmentq);
        segment_destroy(segment);
    }

    if ((segment = segmentq_peek(session->segmentq)) == NULL)
        return NULL;

    if (segment->seq > session->next_seq)
        return NULL;

    if (segment->seq < session->next_seq) {
        offset = session->next_seq - segment->seq;
        segment->seq += offset;
        segment->dataptr += offset;
        segment->length -= offset;
    }

    return segment;
}

void
session_pop(struct session *session)
{
    struct segment *segment = segmentq_pop(session->segmentq);

    if (segment == NULL)
        return;

    session->next_seq += segment->length;
    segment_destroy(segment);
}
