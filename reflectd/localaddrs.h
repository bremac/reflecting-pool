#ifndef _LOCALADDRS_H_
#define _LOCALADDRS_H_

#include <stdint.h>

uint32_t *parse_ips(char *);
uint32_t *load_local_addresses(void);
int is_local_address(uint32_t *, uint32_t);

#endif /* _LOCALADDRS_H_ */
