/* Segment handling and queueing.
 *
 * Based on code from 'Programming Pearls' by Jon Bentley.
 * Copyright (C) 1999 Lucent Technologies
 *
 * You may use this code for any purpose, as long as you leave the
 * copyright notice and book citation attached.
 */

#include <stdlib.h>

#include "segments.h"


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

static inline void
swap(struct segmentq *q, size_t i, size_t j)
{
    struct segment *temp = q->segments[i];
    q->segments[i] = q->segments[j];
    q->segments[j] = temp;
}

struct segmentq *
segmentq_create(size_t maxsize)
{
    struct segmentq *q;

    q = malloc(sizeof(struct segmentq) + sizeof(struct segment *) * maxsize);
    if (q == NULL)
        return NULL;

    q->length = 0;
    q->maxsize = maxsize;
    return q;
}

void
segmentq_destroy(struct segmentq *q)
{
    free(q);
}

int
segmentq_insert(struct segmentq *q, struct segment *segment)
{
    size_t i, p;

    if (q->length + 1 >= q->maxsize)
        return 1;

    q->segments[++q->length] = segment;

    for (i = q->length;
         i > 1 && q->segments[p = i / 2]->seq > q->segments[i]->seq;
         i = p)
        swap(q, p, i);

    return 0;
}

struct segment *
segmentq_peek(struct segmentq *q)
{
    return (q->length == 0) ? NULL : q->segments[1];
}

struct segment *
segmentq_pop(struct segmentq *q)
{
    struct segment *segment;
    size_t i, c;

    if (q->length == 0)
        return NULL;

    segment = q->segments[1];
    q->segments[1] = q->segments[q->length--];

    for (i = 1; (c = 2 * i) <= q->length; i = c) {
        if (c + 1 <= q->length &&
            q->segments[c + 1]->seq < q->segments[c]->seq)
            c++;
        if (q->segments[i]->seq <= q->segments[c]->seq)
            break;
        swap(q, c, i);
    }

    return segment;
}
