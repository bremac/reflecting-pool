#ifndef _SESSIONS_H_
#define _SESSIONS_H_

#include <stddef.h>
#include <stdint.h>
#include <time.h>

#include "definitions.h"
#include "queue.h"


struct segment {
    TAILQ_ENTRY(segment) segments;
    uint64_t seq;
    ssize_t length;
    uint8_t *dataptr;
    uint8_t fin;
    uint8_t rst;
    uint8_t bytes[0];
};

struct session {
    struct session *next;
    TAILQ_HEAD(recv_head, segment) recv_queue;
    TAILQ_HEAD(send_head, segment) send_queue;
    uint64_t next_seq;
    time_t latest_timestamp;
    int fd;
    uint32_t source_ip;
    uint16_t source_port;
    uint8_t is_used;
};

struct sessiontable {
    struct session *lookup[MAX_TCP_SESSIONS];
    struct session sessions[MAX_TCP_SESSIONS];
};

uint64_t adjust_seq(uint32_t, uint64_t);

struct segment *segment_create(size_t);
void segment_destroy(struct segment *);

struct sessiontable *sessiontable_create(void);
void sessiontable_destroy(struct sessiontable *);
void sessiontable_dump(struct sessiontable *);

struct session *session_allocate(struct sessiontable *, uint32_t,
                                 uint16_t, uint32_t);
struct session *session_find(struct sessiontable *, uint32_t, uint16_t);
void session_release(struct sessiontable *, struct session *);

void session_insert(struct sessiontable *, struct session *, struct segment *);
struct segment *session_peek(struct session *);
void session_pop(struct session *);

#endif /* _SESSIONS_H_ */
