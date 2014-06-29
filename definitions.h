#ifndef _DEFINITIONS_H_
#define _DEFINITIONS_H_

#define ARRAYSIZE(a) (sizeof(a) / sizeof(a[0]))

#define LISTEN_PORT       8000
#define RESTRICTED_USER   "bremac"

#define TARGET_HOST       "127.0.0.1"
#define TARGET_PORT       8001

#define MAX_HEADER_BYTES  8 * 1024
#define MAX_WINDOW_BYTES  256 * 1024
#define MAX_WINDOW_SEGS   512
#define MAX_TCP_SESSIONS  200
#define MAX_TIMEOUT_SECS  10

#endif /* _DEFINITIONS_H_ */
