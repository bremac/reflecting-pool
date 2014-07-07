#include <ifaddrs.h>
#include <netinet/in.h>

#include <sys/types.h>

#include <err.h>
#include <stdlib.h>

#include "localaddrs.h"


static int
valid_address(struct ifaddrs *ifaddr)
{
    return ifaddr->ifa_addr != NULL && ifaddr->ifa_addr->sa_family == AF_INET;
}

uint32_t *
load_local_addresses(void)
{
    struct sockaddr_in *sockaddr_in;
    struct ifaddrs *first, *cur;
    size_t i = 0;
    uint32_t *addrs;

    if (getifaddrs(&first)) {
        warn("failed to get interface addresses");
        return NULL;
    }

    for (cur = first; cur != NULL; cur = cur->ifa_next) {
        if (valid_address(cur))
            i++;
    }

    /* The terminator is 0.0.0.0, which is an invalid address. */
    addrs = calloc(i + 1, sizeof(uint32_t));

    if (addrs == NULL) {
        warnx("failed to allocate space for interface addresses");
        return NULL;
    }

    i = 0;
    for (cur = first; cur != NULL; cur = cur->ifa_next) {
        if (valid_address(cur)) {
            sockaddr_in = (struct sockaddr_in *)cur->ifa_addr;
            addrs[i++] = ntohl(sockaddr_in->sin_addr.s_addr);
        }
    }

    freeifaddrs(first);

    return addrs;
}

int
is_local_address(uint32_t *addrs, uint32_t addr)
{
    for (; *addrs; addrs++) {
        if (*addrs == addr)
            return 1;
    }

    return 0;
}
