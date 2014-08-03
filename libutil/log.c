#include <sys/time.h>

#include <errno.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>


static FILE *log_stream = NULL;
static int conn_is_set = 0;
static uint32_t conn_address;
static uint16_t conn_port;


static void
log_timestamp(void)
{
    struct timeval tv;
    struct tm *tm;
    int ret;
    int tz_hour, tz_min;

    gettimeofday(&tv, NULL);

    if ((tm = localtime(&tv.tv_sec)) == NULL)
        goto err;

    tz_hour = abs(tm->tm_gmtoff / 3600);
    tz_min = (tm->tm_gmtoff % 3600) / 60;

    ret = fprintf(log_stream,
                  "%04d-%02d-%02dT%02d:%02d:%02d.%06ld%c%02d:%02d  ",
                  1900 + tm->tm_year, tm->tm_mon + 1, tm->tm_mday,
                  tm->tm_hour, tm->tm_min, tm->tm_sec, (long) tv.tv_usec,
                  tm->tm_gmtoff >= 0 ? '+' : '-', tz_hour, tz_min);

    if (ret < 0)
        goto err;

    return;

err:
    fprintf(log_stream, "(timestamp: %s)  ", strerror(errno));
}

static void
log_conn(void)
{
    if (!conn_is_set)
        return;

    fprintf(log_stream, "[%d.%d.%d.%d:%d] ",
            (0xff000000 & conn_address) >> 24,
            (0x00ff0000 & conn_address) >> 16,
            (0x0000ff00 & conn_address) >> 8,
            0x000000ff & conn_address,
            conn_port);
}

void
log_init(FILE *fp)
{
    log_stream = fp;
}

void
log_set_conn(uint32_t address, uint16_t port)
{
    conn_address = address;
    conn_port = port;
    conn_is_set = 1;
}

void
log_clear_conn(void)
{
    conn_is_set = 0;
}

void
log_msg(const char *format, ...)
{
    va_list ap;

    if (log_stream == NULL)
        return;

    log_timestamp();
    log_conn();

    va_start(ap, format);
    vfprintf(log_stream, format, ap);
    va_end(ap);

    putc('\n', log_stream);
}

void
log_error(const char *format, ...)
{
    va_list ap;
    int error;

    if (log_stream == NULL)
        return;

    error = errno;
    log_timestamp();
    log_conn();

    va_start(ap, format);
    vfprintf(log_stream, format, ap);
    va_end(ap);

    fprintf(log_stream, ": %s", strerror(error));

    putc('\n', log_stream);
}
