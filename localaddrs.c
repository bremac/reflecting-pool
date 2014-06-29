#include <ifaddrs.h>
#include <netinet/in.h>

#include <sys/types.h>

#include <err.h>
#include <stdlib.h>

#include "localaddrs.h"


uint32_t *
load_local_addrs(void)
{
    struct sockaddr_in *sockaddr_in;
    struct ifaddrs *first, *cur;
    size_t i, count = 0;
    uint32_t *addrs;

    if (getifaddrs(&first)) {
        warn("failed to get interface addresses");
        return NULL;
    }

    for (cur = first, i = 0; cur != NULL; cur = cur->ifa_next, i++) {
        if (cur->ifa_addr != NULL)
            count++;
    }

    /* The terminator is 0.0.0.0, which is an invalid address. */
    addrs = calloc(count + 1, sizeof(uint32_t));

    if (addrs == NULL) {
        warnx("failed to allocate space for interface addresses");
        return NULL;
    }

    for (cur = first, i = 0; cur != NULL; cur = cur->ifa_next, i++) {
        if (cur->ifa_addr != NULL) {
            sockaddr_in = (struct sockaddr_in *)cur->ifa_addr;
            addrs[i] = ntohl(sockaddr_in->sin_addr.s_addr);
        }
    }

    return addrs;
}

int
is_local_addr(uint32_t *addrs, uint32_t addr)
{
    for (; *addrs; addrs++) {
        if (*addrs == addr)
            return 1;
    }

    return 0;
}
