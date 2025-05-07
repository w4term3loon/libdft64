#include <sys/socket.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#include "branch_pred.h"
#include "libdft_api.h"
#include "libdft_core.h"
#include "ins_helper.h"
#include "syscall_desc.h"
#include "tagmap.h"

/* syscall descriptors */
extern syscall_desc_t syscall_desc[SYSCALL_MAX];

/* the tag value used for tainting */
static tag_traits<tag_t>::type dta_tag = 1;

static void post_read_hook(THREADID tid, syscall_ctx_t *ctx) {
    /* read() was not successful; optimized branch */
    const size_t nr = ctx->ret;
    if (unlikely(nr <= 0)) return;

    const int fd = ctx->arg[SYSCALL_ARG0];
    const ADDRINT buf = ctx->arg[SYSCALL_ARG1];
    size_t count = ctx->arg[SYSCALL_ARG2];

    printf("[read] fd: %d, addr: %p, size: %lu / %lu\n", fd, (char *)buf, nr, count);
  tagmap_setn(buf, nr, dta_tag);
}

static void
post_write_hook(THREADID tid, syscall_ctx_t *ctx)
{
    const size_t no_of_written_bytes = ctx->ret;
  /* write() was not successful; optimized branch */
  if (unlikely(no_of_written_bytes <= 0)) return;

    const ADDRINT buf = ctx->arg[SYSCALL_ARG1];

  tag_t out_tag = tagmap_getn(buf, no_of_written_bytes);
    if (out_tag == dta_tag) {
        printf("[write] TAINTED write!\n");
    } else {
        printf("[write] clean write!\n");
    }
}

int
main(int argc, char **argv)
{
  /* initialize symbol processing */
  PIN_InitSymbols();

  /* initialize Pin; optimized branch */
  if (unlikely(PIN_Init(argc, argv)))
    /* Pin initialization failed */
    goto err;

  /* initialize the core tagging engine */
  if (unlikely(libdft_init() != 0))
    /* failed */
    goto err;

  (void)syscall_set_post(&syscall_desc[__NR_read], post_read_hook);
  (void)syscall_set_post(&syscall_desc[__NR_write], post_write_hook);

  /* start Pin */
  PIN_StartProgram();

  /* typically not reached; make the compiler happy */
  return EXIT_SUCCESS;

err:  /* error handling */

  /* detach from the process */
  libdft_die();

  /* return */
  return EXIT_FAILURE;
}

