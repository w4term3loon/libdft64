#include "function_desc.h"
#include "function_hook.h"
#include "pin.H"

extern function_desc_t function_desc[FUNCTION_MAX];

static void post_free_hook(THREADID tid, function_ctx_t *ctx) {
    const ADDRINT ret = ctx->ret;
    if ((void *)ret == (void *)-1)
        return;
    const ADDRINT buf = ctx->arg[SYSCALL_ARG0];
    printf("%ld", buf);
    //tagmap_setn(buf, nr, freed_tag);
}

void hook_file_function(){
    (void)function_set_post(&function_desc[__RTN_free], post_free_hook);
}