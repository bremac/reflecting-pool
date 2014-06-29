#include <assert.h>
#include <err.h>
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

static struct session **
sessiontable_findslot(struct sessiontable *table, uint32_t source_ip,
                                            uint16_t source_port)
{
    uint32_t idx;

    for (idx = (sessiontable_hash(source_ip, source_port) %
                ARRAYSIZE(table->lookup));
         table->lookup[idx] != NULL;
         idx = (idx + 1) % ARRAYSIZE(table->lookup)) {
        if (table->lookup[idx] == (struct session *)table) /* Tombstone, skip it */
            continue;

        if (table->lookup[idx]->source_ip == source_ip &&
            table->lookup[idx]->source_port == source_port)
            return &table->lookup[idx];
    }

    return NULL;
}

struct session *
sessiontable_find(struct sessiontable *table, uint32_t source_ip,
                                    uint16_t source_port)
{
    struct session **slot;
    slot = sessiontable_findslot(table, source_ip, source_port);
    return (slot == NULL) ? NULL : *slot;
}

void
sessiontable_insert(struct sessiontable *table, struct session *session)
{
    uint32_t idx = (sessiontable_hash(session->source_ip,
                                      session->source_port) %
                    ARRAYSIZE(table->lookup));

    /* Search until we hit an empty slot or a tombstone. */
    while (table->lookup[idx] != NULL &&
           table->lookup[idx] != (struct session *)table) {
        assert (table->lookup[idx]->source_ip != session->source_ip ||
                table->lookup[idx]->source_port != session->source_port);
        idx = (idx + 1) % ARRAYSIZE(table->lookup);
    }

    table->lookup[idx] = session;
}

void
sessiontable_remove(struct sessiontable *table, struct session *session)
{
    struct session **slot;
    slot = sessiontable_findslot(table, session->source_ip, session->source_port);
    *slot = (struct session *)table;
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
        if (table->sessions[i].state == ST_UNUSED ||
            session_is_dead(&table->sessions[i]))
            break;
    }

    if (i >= ARRAYSIZE(table->sessions))
        return NULL;

    session = &table->sessions[i];

    if (session->state != ST_UNUSED)
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
    session->header_len = 0;
    session->state = ST_HEADER;

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

    if (session == NULL || session->state == ST_UNUSED)
        return;

    if (session->fd >= 0)
        close(session->fd);

    while ((segment = session_peek(session)) != NULL)
        session_pop(session);

    segmentq_destroy(session->segmentq);
    sessiontable_remove(table, session);

    session->state = ST_UNUSED;
}

int
session_insert(struct session *session, struct segment *segment)
{
    return segmentq_insert(session->segmentq, segment);
}

struct segment *
session_peek(struct session *session)
{
    struct segment *segment;
    size_t offset;

    if ((segment = segmentq_peek(session->segmentq)) == NULL)
        return NULL;

    if (segment->seq > session->next_seq)
        return NULL;

    if (segment->seq < session->next_seq) {
        offset = session->next_seq - segment->seq;
        segment->seq += offset;
        segment->dataptr += offset;
    }

    // TODO: Enable header parsing
    //    if (segment->state != ST_BODY)
    //     return NULL;

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
