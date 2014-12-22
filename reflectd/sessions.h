#ifndef _SESSIONS_H_
#define _SESSIONS_H_

#include <stddef.h>
#include <stdint.h>
#include <time.h>

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

struct context {
    uint32_t *local_ips;
    uint32_t *listen_ips;
    int listen_port;

    const char *forward_host;
    const char *forward_port;
    double forward_percentage;

    struct session **lookup;
    struct session *sessions;

    unsigned int max_connections;
    ssize_t window_size_bytes;
    unsigned int timeout_seconds;
};

uint64_t adjust_seq(uint32_t, uint64_t);

struct segment *segment_create(size_t);
void segment_destroy(struct segment *);

struct context *context_init(struct context *, size_t);
void context_teardown(struct context *);
void context_dump(struct context *);

struct session *session_allocate(struct context *, uint32_t,
                                 uint16_t, uint32_t);
struct session *session_find(struct context *, uint32_t, uint16_t);
void session_release(struct context *, struct session *);

void session_insert(struct context *, struct session *, struct segment *);
struct segment *session_peek(struct session *);
void session_pop(struct session *);

#endif /* _SESSIONS_H_ */
