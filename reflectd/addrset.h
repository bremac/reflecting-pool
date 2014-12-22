#ifndef _ADDRSET_H_
#define _ADDRSET_H_

#include <stdint.h>

uint32_t *addrset_from_string(char *);
uint32_t *addrset_local(void);
int addrset_contains(uint32_t *, uint32_t);

#endif /* _ADDRSET_H_ */
