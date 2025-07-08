#include "tf_tools.hpp"

// --- LibC Specific Overrides ---

void
pre_free_hook(tf_hook_ctx_t *ctx) {

  void *addr = (void *)ctx->arg_val[0];
  size_t size = tf_mem_get_size(addr); //< fetch from memmng

  // exists in memmng
  if (addr && size) {
    if (tf_mem_is_freed(addr) && tf_region_check(addr, size)) {
      fprintf(stdout, "[!!!] T%d: free(ptr=0x%p[%zu]), found use after free!\n", ctx->tid, addr,
              size);
      return;
    }

    // clear taint and region from memmng
    tf_mem_free((void *)addr);
    tf_region_clear((void *)addr, size);
    fprintf(stdout, "[OVER] T%d: free(ptr=0x%lx), cleared %zu bytes of taint.\n", ctx->tid,
            (unsigned long)addr, size);

    // apply freed taint, for use after frees
    tf_region_taint((void *)addr, size, TS_FREED, 1);

  } else {
    fprintf(stdout, "[OVER] T%d: free(ptr=NULL) called, unknown address.\n", ctx->tid);
  }
}

void
post_free_hook(tf_hook_ctx_t *ctx) {

  // make sure that MOV instructions do not clear the freed taint
  // fromt the freed memory regions
  trace_uaf_start();
}

int
main(int argc, char **argv) {

  tf_init(argc, argv);

  // register library
  tf_register_all("libc");

  // override hooks manually
  tf_override_func("free", pre_free_hook, post_free_hook);

  // for uaf detection, we check each time ret, if there is uaf tracing, stop it. (can be improved)
  trace_ret_start();

  tf_start();

  return EXIT_SUCCESS;
}

