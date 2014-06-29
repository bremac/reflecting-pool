#ifndef _SEGMENTS_H_
#define _SEGMENTS_H_

#include <stddef.h>
#include <stdint.h>

struct segment {
    uint64_t seq;
    ssize_t length;
    uint8_t *dataptr;
    uint8_t fin;
    uint8_t rst;
    uint8_t bytes[0];
};

struct segmentq {
    size_t length;
    size_t maxsize;
    struct segment *segments[0];
};

struct segment *segment_create(size_t);
void segment_destroy(struct segment *);

struct segmentq *segmentq_create(size_t);
void segmentq_destroy(struct segmentq *);

int segmentq_insert(struct segmentq *, struct segment *);
struct segment *segmentq_peek(struct segmentq *);
struct segment *segmentq_pop(struct segmentq *);

#endif /* _SEGMENTS_H */
