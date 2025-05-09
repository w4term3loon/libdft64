#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include <iostream>

#include "branch_pred.h"
#include "ins_helper.h"
#include "libdft_api.h"
#include "libdft_core.h"
#include "syscall_desc.h"
#include "tagmap.h"

// thread-local storage key
static TLS_KEY func_tls_key;

/* the tag value used for tainting */
/*static tag_traits<tag_t>::type dta_tag = 1;*/

/* function call context definition
 * only up to FUNC_ARG_NUM args are saved
 * TODO: support stack stored arguments (>6)
 */
#define FUNC_ARG_NUM 6
typedef struct {
  ADDRINT address;
  ADDRINT args[FUNC_ARG_NUM];
  ADDRINT retval;
  void *etc;
} func_ctx_t;

typedef void (*func_cb_t)(THREADID, func_ctx_t *);
typedef struct {
  const char *name;
  size_t nargs_to_capture;
  /*bool save_args;*/
  /*bool ret_args;*/
  func_cb_t pre;
  func_cb_t post;
} func_desc_t;

// api
static void
pre_malloc_hook(THREADID tid, func_ctx_t *fct) {
  printf("[HOOK] T%d: pre_malloc(size=%lu) at addr=0x%lx.\n", tid,
         (unsigned long)fct->args[0], (unsigned long)fct->address);
}

// api
static void
post_malloc_hook(THREADID tid, func_ctx_t *fct) {
  printf("[HOOK] T%d: post_malloc(retval=0x%lx) at addr=0x%lx.\n", tid,
         (unsigned long)fct->retval, (unsigned long)fct->address);
}

static func_desc_t malloc_desc = {
    .name = "malloc",
    .nargs_to_capture = 1,
    .pre = pre_malloc_hook,
    .post = post_malloc_hook,
};

/*
 * vcpu_ctx_t
 * virtual CPU (VCPU) context definition;
 * x86/x86_32/i386 arch
 */

/*
 * func_tls_t pre-post mediator TLS
 * similar to syscall thread_ctx_t
 * note: nested instrumented functions will need
 * a tls-stack to store tls types
 */
typedef struct {
  vcpu_ctx_t vcpu;
  func_ctx_t func_ctx;
} func_tls_t;

// internal
static void
pre_malloc_handler(THREADID tid, ADDRINT malloc_arg_size, ADDRINT malloc_address,
                   ADDRINT caller_return_ip) {

  PIN_LockClient();
  IMG img_ip = IMG_FindByAddress(caller_return_ip);
  bool is_from_main = IMG_Valid(img_ip) && IMG_IsMainExecutable(img_ip);
  PIN_UnlockClient();

  // dispose lib calls
  if (!is_from_main) {
    PIN_SetThreadData(func_tls_key, nullptr, tid);
    return;
  }

  func_tls_t *ctx = new func_tls_t();

  ctx->func_ctx.address = malloc_address;
  ctx->func_ctx.args[0] = malloc_arg_size;

  // clear other potential arguments for now
  for (int i = 1; i < FUNC_ARG_NUM; ++i) {
      ctx->func_ctx.args[i] = 0;
  }

  ctx->func_ctx.retval = 0; // not known in pre-hook
  ctx->func_ctx.etc = nullptr;

  // TODO: populate ctx->vcpu if needed.
  // this might involve passing IARG_CONTEXT to this handler
  // and then using PIN_SaveContext() or libdft functions
  // for now, vcpu remains uninitialized unless func_tls_t() default initializes it

  PIN_SetThreadData(func_tls_key, ctx, tid);

  if (malloc_desc.pre != nullptr) {
    malloc_desc.pre(tid, &(ctx->func_ctx));
  }
}

// internal
static void
post_malloc_handler(THREADID tid, ADDRINT return_ptr, ADDRINT malloc_address_from_rtn) {
  // retrieve thread info from tls
  func_tls_t *ctx = static_cast<func_tls_t*>(PIN_GetThreadData(func_tls_key, tid));

  // check if the pre-hook actually stored data
  if (ctx != nullptr) {
    ctx->func_ctx.retval = return_ptr;
    // ctx->func_ctx.address and .args[0] were set by pre_malloc_handler
    // ctx->func_ctx.address should ideally match malloc_address_from_rtn

    // TODO: update ctx->vcpu if needed with post-call CPU state

    if (malloc_desc.post != nullptr) {
      malloc_desc.post(tid, &(ctx->func_ctx));
    }

    delete ctx;
  }

  PIN_SetThreadData(func_tls_key, nullptr, tid);
}

VOID
instrument_image(IMG img, VOID *v) {
  std::cout << "[PIN TOOL] Instrumenting image: " << IMG_Name(img) << std::endl;
  RTN rtn_malloc = RTN_FindByName(img, malloc_desc.name);

  // found malloc def in img
  if (RTN_Valid(rtn_malloc)) {
    std::cout << "[PIN TOOL] Found malloc." << std::endl;
    RTN_Open(rtn_malloc);

    // pre-hook handler
    RTN_InsertCall(rtn_malloc, IPOINT_BEFORE, (AFUNPTR)pre_malloc_handler, IARG_THREAD_ID,
                   IARG_FUNCARG_ENTRYPOINT_VALUE, 0, // pass mallocs 1st arg (size)
                   IARG_INST_PTR,                    // pass the address of the malloc routine
                   IARG_RETURN_IP,                   // pass caller ip
                   IARG_END);

    // post-hook handler
    RTN_InsertCall(rtn_malloc, IPOINT_AFTER,
        (AFUNPTR)post_malloc_handler,
        IARG_THREAD_ID,
        IARG_FUNCRET_EXITPOINT_VALUE,
        IARG_ADDRINT,
        RTN_Address(rtn_malloc), // address of malloc itself, for context
        IARG_END);
    RTN_Close(rtn_malloc);
  }
}

int
main(int argc, char **argv) {
  // initialize symbol processing
  PIN_InitSymbols();

  // initialize pin
  if (unlikely(PIN_Init(argc, argv))) {
    goto err;
  }

  // allocate the TLS key
  func_tls_key = PIN_CreateThreadDataKey(nullptr);
  if (func_tls_key == INVALID_TLS_KEY) {
    std::cerr << "[PINTOOL ERROR] Cannot allocate TLS key." << std::endl;
    goto err;
  }

  // initialize the core tagging engine
  /*if (unlikely(libdft_init() != 0))*/
  /*  goto err;*/

  // add entry point
  IMG_AddInstrumentFunction(instrument_image, 0);

  // start pin
  PIN_StartProgram();

  // free the TLS
  PIN_DeleteThreadDataKey(func_tls_key);

  // make the compiler happy
  return EXIT_SUCCESS;

err:
  // detach from the process
  /*libdft_die();*/
  return EXIT_FAILURE;
}
