#include <stdio.h>
#include <stdlib.h>

int
main() {
  printf("[APP] Calling malloc...\n");
  char *p = (char *)malloc(10);
  printf("[APP] malloc returned %p\n", p);

  scanf("%5s", p);

  printf("[APP] Calling system...\n");
  system((const char *)p);
  printf("[APP] system returned %p\n", p);

  if (p)
    free(p);
  printf("[APP] Done.\n");
  return 0;
}
