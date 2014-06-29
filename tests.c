#include <assert.h>
#include <stdlib.h>
#include <stdio.h>

#include "localaddrs.h"
#include "segments.h"
#include "sessions.h"

void
test_localaddrs(void)
{
  uint32_t *addrs = load_local_addrs();

  assert(addrs != NULL);
  assert(is_local_addr(addrs, 0x7f000001));  /* 127.0.0.1 is always local */
  assert(!is_local_addr(addrs, 0x08080808)); /* 8.8.8.8 is Google's DNS. */
}

void
test_adjust_seq(void)
{
  /* Sequence numbers outside of the window are invalid */
  assert(adjust_seq(1, 1) == 1);
  assert(adjust_seq(1, 0) == 1);
  assert(adjust_seq(0, 1) == SEQ_INVALID);

  /* Wrapped-around sequence numbers are corrected */
  assert(adjust_seq(0, 0xffffffff) == 0x100000000);
  assert(adjust_seq(0x0fffffff, 0xffffffff) == SEQ_INVALID);
  assert(adjust_seq(1, 0x2ffffffff) == 0x300000001);
}

int
main(void)
{
  test_adjust_seq();
  test_localaddrs();

  puts("All tests passed");

  return EXIT_SUCCESS;
}
