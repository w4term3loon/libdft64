#include <stdio.h>
#include <stdlib.h>

int
main() {
  printf("[APP]: Calling malloc...\n");
  void *p = malloc(10);
  printf("[APP]: malloc returned %p\n", p);
  if (p)
    free(p);
  printf("[APP]: Done.\n");
  return 0;
}
