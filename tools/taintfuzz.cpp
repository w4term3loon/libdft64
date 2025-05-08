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

/* the tag value used for tainting */
/*static tag_traits<tag_t>::type dta_tag = 1;*/

/* function call context definition
 * only up to FUNC_ARG_NUM args are saved
 * TODO: support stack stored arguments (>6)
 */
#define NO false
#define YES true
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

static void
pre_malloc_hook(THREADID tid, func_ctx_t *fct) {
  printf("[HOOK] T%d: pre_malloc(size=%lu) at addr=0x%lx. Hello!\n", tid,
         (unsigned long)fct->args[0], (unsigned long)fct->address);
}

static func_desc_t malloc_desc = {
    .name = "malloc",
    .nargs_to_capture = 1,
    .pre = pre_malloc_hook,
    .post = nullptr,
};

static void
pre_malloc_handler(THREADID tid, ADDRINT malloc_arg_size, ADDRINT malloc_address, ADDRINT caller_return_ip) {

  PIN_LockClient();
  IMG img_ip = IMG_FindByAddress(caller_return_ip);
  bool is_from_main = IMG_Valid(img_ip) && IMG_IsMainExecutable(img_ip);
  PIN_UnlockClient();

  // dispose lib calls
  if (!is_from_main) {
    return;
  }

  func_ctx_t ctx;
  ctx.address = malloc_address; // Address of malloc itself
  ctx.args[0] = malloc_arg_size;

  // other args are discarded for now
  for (int i = 1; i < FUNC_ARG_NUM; ++i) {
    ctx.args[i] = 0;
  }

  ctx.retval = 0; // unknown in pre-hook
  ctx.etc = nullptr;

  if (malloc_desc.pre != nullptr) {
    malloc_desc.pre(tid, &ctx);
  } else {
    // Fallback or direct call if not using malloc_desc for dispatch here
    // pre_malloc_hook(tid, &current_context);
    printf("[PIN TOOL HANDLER] pre-hook was uninitialised.\n");
  }
}

VOID
instrument_image(IMG img, VOID *v) {
  std::cout << "[PIN TOOL] Instrumenting image: " << IMG_Name(img) << std::endl;
  RTN rtn_malloc = RTN_FindByName(img, malloc_desc.name);
  if (RTN_Valid(rtn_malloc)) {
    std::cout << "[PIN TOOL] Found malloc." << std::endl;
    RTN_Open(rtn_malloc);
    RTN_InsertCall(rtn_malloc, IPOINT_BEFORE,
               (AFUNPTR)pre_malloc_handler,
               IARG_THREAD_ID,
               IARG_FUNCARG_ENTRYPOINT_VALUE, 0,   // pass mallocs 1st arg (size)
               IARG_INST_PTR,                      // pass the address of the malloc routine
               IARG_RETURN_IP,
               IARG_END);
    RTN_Close(rtn_malloc);
  }
}

int
main(int argc, char **argv) {
  // initialize symbol processing
  PIN_InitSymbols();

  // initialize pin
  if (unlikely(PIN_Init(argc, argv)))
    goto err;

  // initialize the core tagging engine
  /*if (unlikely(libdft_init() != 0))*/
  /*  goto err;*/

  // add entry point
  IMG_AddInstrumentFunction(instrument_image, 0);

  // start pin
  PIN_StartProgram();

  // make the compiler happy
  return EXIT_SUCCESS;

err:
  // detach from the process
  /*libdft_die();*/
  return EXIT_FAILURE;
}
