#ifndef _SESSIONS_H_
#define _SESSIONS_H_

#include <stdint.h>
#include <time.h>

#include "definitions.h"
#include "segments.h"


#define SEQ_INVALID UINT64_MAX

struct session {
  struct segmentq *segmentq;
  uint64_t next_seq;
  time_t latest_timestamp;
  uint32_t source_ip;
  uint16_t source_port;

  int fd;
  char header[MAX_HEADER_BYTES];
  size_t header_len;

  enum { ST_UNUSED, ST_HEADER, ST_BODY } state;
};

struct sessiontable {
  struct session *lookup[2 * MAX_TCP_SESSIONS];
  struct session sessions[MAX_TCP_SESSIONS];
};

uint64_t adjust_seq(uint32_t, uint64_t);

struct sessiontable *sessiontable_create(void);

struct session *session_allocate(struct sessiontable *, uint32_t,
                                 uint16_t, uint32_t);
struct session *session_find(struct sessiontable *, uint32_t, uint16_t);
void session_release(struct sessiontable *, struct session *);

int session_insert(struct session *, struct segment *);
struct segment *session_peek(struct session *);
void session_pop(struct session *);

#endif /* _SESSIONS_H_ */
