#ifndef _LOCALADDRS_H_
#define _LOCALADDRS_H_

#include <stdint.h>

uint32_t *load_local_addrs(void);
int is_local_addr(uint32_t *addrs, uint32_t addr);

#endif /* _LOCALADDRS_H_ */
