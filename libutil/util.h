#ifndef _UTIL_H_
#define _UTIL_H_

#include <inttypes.h>
#include <stdio.h>

int config_read(FILE *, char **, char **, int *);

void log_init(FILE *);
void log_set_conn(uint32_t, uint16_t);
void log_clear_conn(void);
void log_error(const char *format, ...)
    __attribute__ ((format (printf, 1, 2)));
void log_msg(const char *format, ...)
    __attribute__ ((format (printf, 1, 2)));

int pidfile(const char *);

void setuser(const char *);

long long strtonum(const char *, long long, long long, const char **);

#endif /* _UTIL_H_ */
