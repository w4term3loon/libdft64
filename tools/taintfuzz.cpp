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

#define DEBUG_TAINT 1
#include "taint.hpp"

// thread-local storage key
// TODO: buffer it
static TLS_KEY func_tls_key;

/*
 * exposed hook context
 * TODO: support stack stored arguments (>6)
 */
#define FUNC_ARG_NUM 6
typedef struct {
  const char *name;
  ADDRINT address;
  ADDRINT args[FUNC_ARG_NUM];
  ADDRINT retval;
  void *etc;
} tf_hook_ctx_t;

/*
 * library struct
 * function desctiption function
 */
typedef void (*func_cb_t)(THREADID, tf_hook_ctx_t *);
typedef struct {
  const char *name;
  size_t nargs;
  /*bool save_args;*/
  /*bool ret_args;*/
  func_cb_t pre;
  func_cb_t post;
} func_desc_t;

/*
 * vcpu_ctx_t
 * virtual CPU (VCPU) context definition;
 * x86/x86_32/i386 arch
 *
 * tf_thread_ctx_t pre-post mediator TLS
 * similar to syscall tf_thread_ctx_t
 * TODO: nested instrumented functions will need
 * a tls-stack to store tls types
 */
typedef struct {
  vcpu_ctx_t vcpu;
  tf_hook_ctx_t func_ctx;
} tf_thread_ctx_t;

// api
void
pre_system_hook(THREADID tid, tf_hook_ctx_t *fct) {
  const char *string = (const char *)fct->args[0];
  if (tf_is_memory_tainted((void *)string, 10)) { // Check length + null terminator (10 bytes)
    printf("[SNK] T%d: system(string=%s) argument is tainted.\n", tid, string);
  } else {
    printf("[SNK] No taint found via tf_is_memory_tainted.\n");
  }
}

static void
pre_malloc_hook(THREADID tid, tf_hook_ctx_t *fct) {
  size_t size = (size_t)fct->args[0];

  printf("[PRE] T%d: pre_malloc(size=%lu) at addr=0x%lx.\n", tid, size,
         (unsigned long)fct->address);

  tf_thread_ctx_t *call_ctx = static_cast<tf_thread_ctx_t *>(PIN_GetThreadData(func_tls_key, tid));
  if (call_ctx) {
    call_ctx->func_ctx.etc = (void *)size;
  } else {
    fprintf(stderr, "[ERR] T%d: Could not get TLS context in pre_malloc_hook for %s\n", tid,
            fct->name);
  }
  fct->etc = (void *)size;
}

// api
static void
post_malloc_hook(THREADID tid, tf_hook_ctx_t *fct) {
  void *ptr = (void *)fct->retval;
  size_t size = (size_t)fct->etc;

  printf("[PST] T%d: post_malloc(ptr=0x%lx, size=%lu) at addr=0x%lx.\n", tid, (unsigned long)ptr,
         size, (unsigned long)fct->address);

  if (ptr != nullptr && size > 0) {
    // track the allocation
    tf_track_allocation(ptr, size);

    // use heap source type with level 1, and allocation size as ID
    tf_taint_memory(ptr, size, TS_HEAP, 1, size, "heap allocation");
  }
}

/*
 * store all registered function hooks
 * so later they can be used if needed
 * returns hook id
 */
static std::map<std::string, func_desc_t> tf_hook_registry;
int
tf_register_func(std::string func_name, size_t nargs, func_cb_t pre, func_cb_t post) {

  // sanity check
  if (nargs > FUNC_ARG_NUM) {
    std::cerr << "[ERR] Cannot capture more than " << FUNC_ARG_NUM
              << " arguments for function: " << func_name << std::endl;
    return false;
  }

  func_desc_t desc;
  desc.name = strdup(func_name.c_str()); // can leak
  desc.nargs = nargs;
  desc.pre = pre;
  desc.post = post;

  tf_hook_registry[func_name] = desc;

  std::cout << "[INF] Registered hook for function: " << func_name << " with " << nargs << " args"
            << std::endl;

  return true;
}

// internal
VOID
tf_pre_handler(THREADID tid, CONTEXT *ctx, ADDRINT func_addr, ADDRINT arg0, ADDRINT arg1,
               ADDRINT arg2, ADDRINT arg3, ADDRINT arg4, ADDRINT arg5, ADDRINT return_ip) {

  // optimize (?)
  PIN_LockClient();
  std::string func_name = RTN_FindNameByAddress(func_addr);
  PIN_UnlockClient();

  // find the descriptor for func
  auto it = tf_hook_registry.begin();
  for (; it != tf_hook_registry.end(); ++it) {
    if (func_name.find(it->first) != std::string::npos)
      break;
  }

  // sanity check
  if (it == tf_hook_registry.end()) {
    return;
  }

  // check if this call is from the main executable
  PIN_LockClient();
  IMG img_ip = IMG_FindByAddress(return_ip);
  bool is_from_main = IMG_Valid(img_ip) && IMG_IsMainExecutable(img_ip);
  PIN_UnlockClient();

  // skip if internal library call
  // TODO: smarter blacklisting
  if (!is_from_main) {
    PIN_SetThreadData(func_tls_key, nullptr, tid);
    return;
  }

  // create context for this function call
  tf_thread_ctx_t *call_ctx = new tf_thread_ctx_t();
  call_ctx->func_ctx.address = func_addr;

  // store the arguments based on how many we should capture
  size_t nargs = it->second.nargs;
  if (nargs >= 1)
    call_ctx->func_ctx.args[0] = arg0;
  if (nargs >= 2)
    call_ctx->func_ctx.args[1] = arg1;
  if (nargs >= 3)
    call_ctx->func_ctx.args[2] = arg2;
  if (nargs >= 4)
    call_ctx->func_ctx.args[3] = arg3;
  if (nargs >= 5)
    call_ctx->func_ctx.args[4] = arg4;
  if (nargs >= 6)
    call_ctx->func_ctx.args[5] = arg5;

  // store the function context in TLS
  PIN_SetThreadData(func_tls_key, call_ctx, tid);

  // call the pre-hook callback if registered
  if (it->second.pre != nullptr) {
    it->second.pre(tid, &(call_ctx->func_ctx));
  }
}

// internal
VOID
tf_post_handler(THREADID tid, CONTEXT *ctx, ADDRINT func_addr, ADDRINT ret_val) {
  // get thread info from TLS
  tf_thread_ctx_t *call_ctx = static_cast<tf_thread_ctx_t *>(PIN_GetThreadData(func_tls_key, tid));

  // check if the pre-hook stored data
  // TODO: it should work without pre-hooks
  if (call_ctx != nullptr) {
    // store the return value
    call_ctx->func_ctx.retval = ret_val;

    // find the function name
    PIN_LockClient();
    std::string func_name = RTN_FindNameByAddress(func_addr);
    PIN_UnlockClient();

    // find the hook descriptor
    auto it = tf_hook_registry.begin();
    for (; it != tf_hook_registry.end(); ++it) {
      if (func_name.find(it->first) != std::string::npos)
        break;
    }

    if (it != tf_hook_registry.end() && it->second.post != nullptr) {
      // call the post-hook callback
      it->second.post(tid, &(call_ctx->func_ctx));
    }

    delete call_ctx;
  }

  PIN_SetThreadData(func_tls_key, nullptr, tid);
}

VOID
tf_instrument_func(RTN rtn) {
  std::string func_name = RTN_Name(rtn);

  // check for hook
  auto it = tf_hook_registry.find(func_name);
  if (it == tf_hook_registry.end()) {
    // partial matching for c++ mangled names
    // TODO: this might bite us in the ass later
    for (it = tf_hook_registry.begin(); it != tf_hook_registry.end(); ++it) {
      if (func_name.find(it->first) != std::string::npos) {
        break;
      }
    }

    if (it == tf_hook_registry.end()) {
      return; // no hook registered for this function
    }
  }

  std::cout << "[INF] Instrumenting function: " << func_name << std::endl;

  RTN_Open(rtn);

  // insert pre-hook handler
  RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)tf_pre_handler, IARG_THREAD_ID,
                 IARG_CONTEXT,                   // CPU context for register access
                 IARG_ADDRINT, RTN_Address(rtn), // function address
                 // pass first 6 arguments (x86-64 calling convention)
                 IARG_FUNCARG_ENTRYPOINT_VALUE, 0, IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
                 IARG_FUNCARG_ENTRYPOINT_VALUE, 2, IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
                 IARG_FUNCARG_ENTRYPOINT_VALUE, 4, IARG_FUNCARG_ENTRYPOINT_VALUE, 5,
                 IARG_RETURN_IP, // caller's return address
                 IARG_END);

  // insert post-hook handler if we have a post callback
  if (it->second.post != nullptr) {
    RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)tf_post_handler, IARG_THREAD_ID,
                   IARG_CONTEXT,                   // CPU context for register access
                   IARG_ADDRINT, RTN_Address(rtn), // function address
                   IARG_FUNCRET_EXITPOINT_VALUE,   // return value
                   IARG_END);
  }

  RTN_Close(rtn);
}

VOID
tf_instrument_img(IMG img) {
  std::cout << "[INF] Processing image: " << IMG_Name(img) << std::endl;

  // each section in the image
  for (SEC sec = IMG_SecHead(img); SEC_Valid(sec); sec = SEC_Next(sec)) {
    // each routine in the section
    for (RTN rtn = SEC_RtnHead(sec); RTN_Valid(rtn); rtn = RTN_Next(rtn)) {
      // migth need to optimize, this checks for every single function
      tf_instrument_func(rtn);
    }
  }
}

int
main(int argc, char **argv) {

  // init pin and symbols
  PIN_InitSymbols();
  if (unlikely(PIN_Init(argc, argv))) {
    goto err;
  }

  // allocate the TLS key
  func_tls_key = PIN_CreateThreadDataKey(nullptr);
  if (func_tls_key == INVALID_TLS_KEY) {
    std::cerr << "[ERR] Cannot allocate TLS key." << std::endl;
    goto err;
  }

  // init libdft
  if (unlikely(libdft_init() != 0)) {
    std::cerr << "[ERR] Failed to initialize libdft." << std::endl;
    goto err;
  }

  // register malloc & send
  tf_register_func("__libc_malloc", 1, pre_malloc_hook, post_malloc_hook);
  tf_register_func("__libc_system", 1, pre_system_hook, nullptr);

  // TODO: register all functions of a loaded library

  // Register image instrumentation
  IMG_AddInstrumentFunction([](IMG img, VOID *v) { tf_instrument_img(img); }, 0);

  // start pin
  PIN_StartProgram();

  // free the TLS
  PIN_DeleteThreadDataKey(func_tls_key);

  // make the compiler happy
  return EXIT_SUCCESS;

err:
  libdft_die();
  return EXIT_FAILURE;
}
