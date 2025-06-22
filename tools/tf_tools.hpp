#ifndef TF_TOOLS_H
#define TF_TOOLS_H

#include <map>

#include "pin.H"

#include "tf_mem.hpp"

#define DEBUG_TAINT
#define TAINT_IMPLEMENTATION
#include "tf_taint.h"

#include "tf_gen.hpp"

/*
 * Exposed context for pre-post HOOK communication
 */
struct tf_hook_ctx_t {
  THREADID tid;
  std::string name;
  ADDRINT func_addr;
  std::vector<ADDRINT *> arg_addr;
  std::vector<ADDRINT> arg_val;
  ADDRINT ret_val;
  uintptr_t etc;
};

// --- Generic Hook Callbacks ---
static void
generic_pre(tf_hook_ctx_t *ctx) {

  // fetch the memory mapping
  // from /proc/self/maps
  // TODO: find a balance, when to call
  // maybe monitor memory usage and only refresh when kernel is suspected to allocate a new page
  refresh_memory_map();

  uint32_t flags = *((uint32_t *)ctx->etc);

  // SOURCE
  if (flags & IO_SRC) {
    fprintf(stdout, "[PRE] Found source: %s\n", ctx->name.c_str());
  }

  // SINK
  if (flags & IO_SINK) {
    fprintf(stdout, "[PRE] Found sink: %s\n", ctx->name.c_str());

    // iterate over argument values
    for (size_t i = 0; i < ctx->arg_val.size(); i++) {
      tf_type_t type = tf_check_type(ctx->arg_val[i]);

      // pointer input values in the accessible
      // memory regions
      if (type == HEAP_PTR || type == STACK_PTR) {

        size_t len = tf_mem_get_size((void *)ctx->arg_val[i]);
        if (len > 0 && tf_region_check((void *)ctx->arg_val[i], len)) {
          fprintf(stdout, "[!!!] ALERT: SINK %s touched tainted data at 0x%lx\n", ctx->name.c_str(),
                  ctx->arg_val[i]);
        }
      }

      // mapped memory regions
      else if (type == MAPPED_PTR || type == LIB_PTR) {
        // TODO: probbably should not fidget there, but data values are sometimes there
        // check for TS_ENVIRONMENT
        tf_region_check((void *)ctx->arg_val[i], 1);
      }

      // skip null values
      else if (type == NULL_PTR || type == UNKNOWN) {
        continue;
      }

      else {
        // check the smalles int storage value amount of bytes
        // to make sure to avoid false positives
        // TODO: get size from heuristics
        tf_region_check((void *)ctx->arg_addr[i], sizeof(short));
      }
    }
  }
}

static void
generic_post(tf_hook_ctx_t *ctx) {

  // fetch the memory mapping
  // from /proc/self/maps
  // TODO: find a balance, when to call
  // maybe monitor memory usage and only refresh when kernel is suspected to allocate a new page
  refresh_memory_map();

  // get classification
  uint32_t flags = *((uint32_t *)ctx->etc);

  // SOURCE
  if (flags & IO_SRC) {
    fprintf(stdout, "[PST] Found source: %s\n", ctx->name.c_str());

    // RETURN: suspect allocation if return value points to HEAP
    // suspect string return if points to the stack
    if (ctx->ret_val != 0) {

      // classify the return type
      tf_type_t ret_type = tf_check_type(ctx->ret_val);

      if (ret_type == HEAP_PTR) {
        for (size_t i = 0; i < ctx->arg_val.size(); i++) {

          // TODO: use first now, come up with better
          // if we find a size argument
          if (tf_check_type(ctx->arg_val[i]) == SIZE_ARG) {

            size_t potential_size = (size_t)ctx->arg_val[i];

            // register and taint memory region
            tf_mem_register((void *)ctx->ret_val, potential_size);
            tf_region_taint((void *)ctx->ret_val, potential_size, TS_HEAP, 1);
            fprintf(stdout, "[TNT] Marked return value 0x%lx[%zu] as tainted\n", ctx->ret_val,
                    potential_size);

            break;
          }
        }
      }

      // THIS NEVER HAPPENS IN C
      // strings or buffer, same method
      else if (ret_type == STACK_PTR) {
        for (size_t i = 0; i < ctx->arg_val.size(); i++) {

          // TODO: use first now, come up with better
          // if we find a size argument
          if (tf_check_type(ctx->arg_val[i]) == SIZE_ARG) {

            size_t potential_size = (size_t)ctx->arg_val[i];

            // register and taint memory region
            tf_mem_register((void *)ctx->ret_val, potential_size);
            tf_region_taint((void *)ctx->ret_val, potential_size, TS_NONE, 1);
            fprintf(stdout, "[TNT] Marked return value 0x%lx[%zu] as tainted\n", ctx->ret_val,
                    potential_size);

            break;
          }
        }
      }

      else if (ret_type == INVALID_PTR) {
        fprintf(stdout, "[TNT] Return value 0x%lx is invalid pointer - not tainting\n",
                ctx->ret_val);
      }

      // TODO: this usually allocates memory internally
      // or just points to the data section that is on the readonly stack
      else if (ret_type == LIB_PTR || ret_type == MAPPED_PTR) {
        tf_region_taint((void *)ctx->ret_val, 1, TS_ENVIRONMENT, 1);
        fprintf(stdout, "[TNT] Return value 0x%lx points to library/mapped memory - monitoring\n",
                ctx->ret_val);
      }

      else {
        // NUMERICAL VALUES
        // TODO: what do we do here? maybe propagate the return register to taint that??
      }
    }

    // OUTPUT PARAMS: check if there were any pointers
    for (size_t i = 0; i < ctx->arg_val.size(); ++i) {

      ADDRINT arg = ctx->arg_val[i];
      tf_type_t arg_type = tf_check_type(arg);

      // if output pointer points to heap (or stack) <-unlikely
      if (arg_type == HEAP_PTR || arg_type == STACK_PTR) {
        size_t len = 0;

        // NAIVE APPROACH: find first size-like value in remaining arguments
        // since this is a common pattern in functions, its a good approximation
        for (size_t j = i + 1; j < ctx->arg_val.size(); ++j) {
          ADDRINT potential_size = ctx->arg_val[j];

          // use the first size parameter
          if (tf_check_type(potential_size)) {
            len = potential_size;
            fprintf(stdout, "[TNT] Using arg[%zu] = %zu as size for pointer arg[%zu] = 0x%lx\n", j,
                    len, i, arg);
            break;
          }
        }

        if (len > 0) {
          switch (arg_type) {

          case HEAP_PTR:
            tf_region_taint((void *)arg, len, TS_HEAP, 1);
            fprintf(stdout, "[TNT] Marked arg[%zu] = 0x%lx[%zu] as tainted on HEAP\n", i, arg, len);
            break;

          case STACK_PTR:
            tf_region_taint((void *)arg, len, TS_ARGUMENT, 1);
            fprintf(stdout, "[TNT] Marked arg[%zu] = 0x%lx[%zu] as tainted on STACK\n", i, arg,
                    len);
            break;

          default:
            assert(0); //< unreachable
            break;
          }
        }

        else {
          fprintf(stdout, "[TNT] Out param arg[%zu] = 0x%lx[%zu] was not registered.\n", i, arg,
                  len);
        }
      }
    }
  }

  // SINK
  if (flags & IO_SINK) {
    fprintf(stdout, "[PST] Found sink: %s\n", ctx->name.c_str());
  }
}

// --- LibC Specific Overrides ---
// TODO: move to the demo
ins_desc_t tf_ins_desc[XED_ICLASS_LAST];
#include "logger.h"
Logger logger;

void
trace_uaf(INS ins);

void
trace_uaf_start() {
  xed_iclass_enum_t ins_indx;
  ins_indx = XED_ICLASS_MOV;
  if (unlikely(tf_ins_desc[ins_indx].pre == NULL))
    tf_ins_desc[ins_indx].pre = trace_uaf;
}

void
trace_uaf_stop() {
  xed_iclass_enum_t ins_indx;
  ins_indx = XED_ICLASS_MOV;
  if (unlikely(tf_ins_desc[ins_indx].pre == trace_uaf))
    tf_ins_desc[ins_indx].pre = NULL;
}

void
uaf(ADDRINT dst) {
  // printf("memory: %lx\n", dst);
  if (tag_uaf_getb(dst)) {
    // logger.store_ins(TT_UAF, dst);
  }
}

void
trace_uaf(INS ins) {
  if (INS_OperandIsMemory(ins, 0)) {
    INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)uaf, IARG_FAST_ANALYSIS_CALL, IARG_MEMORYWRITE_EA,
                   IARG_END);
    trace_uaf_stop(); // TODO add stop point for uaf
  }
}

void
pre_free_hook(tf_hook_ctx_t *ctx) {

  void *addr = (void *)ctx->arg_val[0];
  size_t size = tf_mem_get_size(addr); //< fetch from memmng

  // exists in memmng
  if (addr && size) {
    if (tf_mem_is_freed(addr) && tf_region_check(addr, size)) {
      fprintf(stdout, "[!!!] T%d: free(ptr=0x%p[%zu]), found use after free!\n", ctx->tid,
              addr, size);
      return;
    }

    // clear taint and region from memmng
    tf_mem_free((void *)addr);
    tf_region_clear((void *)addr, size);
    fprintf(stdout, "[PFH] T%d: free(ptr=0x%lx), cleared %zu bytes of taint.\n", ctx->tid,
            (unsigned long)addr, size);

    // apply freed taint, for use after frees
    tf_region_taint((void *)addr, size, TS_FREED, 1);

  } else {
    fprintf(stdout, "[PFH] T%d: free(ptr=NULL) called, unknown address.\n", ctx->tid);
  }
}

void
post_free_hook(tf_hook_ctx_t *ctx) {

  // make sure that MOV instructions do not clear the freed taint
  // fromt the freed memory regions
  trace_uaf_start();
}

/*
 * Internal function registry
 */
using func_cb_t = void (*)(tf_hook_ctx_t *);
struct hook_t {
  sig_entry_t *sig;
  func_cb_t pre;
  func_cb_t post;
};

static std::map<std::string, hook_t> tf_func_registry;

void
tf_override_func(std::string name, func_cb_t pre, func_cb_t post) {
  auto it = tf_func_registry.find(name);
  if (it == tf_func_registry.end()) {
    fprintf(stdout, "[INF] Function %s is not yet registered.\n", name.c_str());
    return;
  }

  tf_func_registry[name].pre = pre;
  tf_func_registry[name].post = post;
}

void
tf_register_func(sig_entry_t *sig, func_cb_t pre, func_cb_t post) {
  auto it = tf_func_registry.find(sig->name);
  if (it != tf_func_registry.end()) {
    fprintf(stdout, "[INF] Function %s already registered, skipping\n", sig->name.c_str());
    return;
  }
  tf_func_registry[sig->name] = hook_t{sig, pre, post};
  fprintf(stdout, "[INF] Registered function: %s\n", sig->name.c_str());
}

void
tf_register_all() {
  for (sig_entry_t &s : tf_sig_table) {
    tf_register_func(&s, generic_pre, generic_post);
  }
}

/*
 * Thread-local context for pre-post HANDLER communication
 */
struct tf_thread_ctx_t {
  vcpu_ctx_t vcpu;
  tf_hook_ctx_t func_ctx;
};

// Thread-local storage key
static TLS_KEY func_tls_key;

// --- Pin Instrumentation Callbacks ---
static VOID
tf_pre_handler(THREADID tid, CONTEXT *ctx, ADDRINT func_addr, ADDRINT ret_addr, UINT32 nargs,
               ADDRINT *arg0_addr, ADDRINT arg0_val, ADDRINT *arg1_addr, ADDRINT arg1_val,
               ADDRINT *arg2_addr, ADDRINT arg2_val, ADDRINT *arg3_addr, ADDRINT arg3_val,
               ADDRINT *arg4_addr, ADDRINT arg4_val, ADDRINT *arg5_addr, ADDRINT arg5_val) {

  // NOTE: no need to lock if symbols are initialized
  PIN_LockClient();
  std::string func_name = RTN_FindNameByAddress(func_addr);
  IMG img_addr = IMG_FindByAddress(ret_addr);
  bool is_from_main = IMG_Valid(img_addr) && IMG_IsMainExecutable(img_addr);
  PIN_UnlockClient();

  // skip if internal library call
  // TODO: smarter blacklisting
  if (!is_from_main) {
    PIN_SetThreadData(func_tls_key, NULL, tid);
    return;
  }

  // find the descriptor for func
  auto func = tf_func_registry.begin();
  for (; func != tf_func_registry.end(); ++func) {
    if (func_name.find(func->first) != std::string::npos)
      break;
  }

  // sanity check
  if (func == tf_func_registry.end()) {
    PIN_SetThreadData(func_tls_key, NULL, tid); // ensure TLS is cleared
    return;
  }

  tf_thread_ctx_t *thread_ctx = new tf_thread_ctx_t();
  if (!thread_ctx) {
    fprintf(stderr, "[ERR] T%d: Failed to allocate tf_thread_ctx_t for %s\n", tid,
            func_name.c_str());
    PIN_SetThreadData(func_tls_key, NULL, tid);
    return;
  }

  thread_ctx->func_ctx.name = func->first;
  thread_ctx->func_ctx.tid = tid;
  thread_ctx->func_ctx.func_addr = func_addr;
  thread_ctx->func_ctx.ret_val = 0;
  thread_ctx->func_ctx.etc = (uintptr_t)&(func->second.sig->flags); // hand over flags

  // clear args vectors before adding new arguments
  thread_ctx->func_ctx.arg_addr.clear();
  thread_ctx->func_ctx.arg_val.clear();

  // add only the arguments the function expects
  if (nargs > 0) {
    thread_ctx->func_ctx.arg_addr.push_back(arg0_addr);
    thread_ctx->func_ctx.arg_val.push_back(arg0_val);
  }
  if (nargs > 1) {
    thread_ctx->func_ctx.arg_addr.push_back(arg1_addr);
    thread_ctx->func_ctx.arg_val.push_back(arg1_val);
  }
  if (nargs > 2) {
    thread_ctx->func_ctx.arg_addr.push_back(arg2_addr);
    thread_ctx->func_ctx.arg_val.push_back(arg2_val);
  }
  if (nargs > 3) {
    thread_ctx->func_ctx.arg_addr.push_back(arg3_addr);
    thread_ctx->func_ctx.arg_val.push_back(arg3_val);
  }
  if (nargs > 4) {
    thread_ctx->func_ctx.arg_addr.push_back(arg4_addr);
    thread_ctx->func_ctx.arg_val.push_back(arg4_val);
  }
  if (nargs > 5) {
    thread_ctx->func_ctx.arg_addr.push_back(arg5_addr);
    thread_ctx->func_ctx.arg_val.push_back(arg5_val);
  }

  PIN_SetThreadData(func_tls_key, thread_ctx, tid);

  // CALL the pre-hook callback if registered
  if (func->second.pre != nullptr) {
    func->second.pre(&(thread_ctx->func_ctx));
  }
}

static VOID
tf_post_handler(THREADID tid, CONTEXT *ctx, ADDRINT func_addr, ADDRINT ret_val) {
  tf_thread_ctx_t *thread_ctx = (tf_thread_ctx_t *)PIN_GetThreadData(func_tls_key, tid);

  if (thread_ctx != NULL) {
    thread_ctx->func_ctx.ret_val = ret_val;

    PIN_LockClient();
    std::string func_name = RTN_FindNameByAddress(func_addr);
    PIN_UnlockClient();

    // find the descriptor for func
    auto func = tf_func_registry.begin();
    for (; func != tf_func_registry.end(); ++func) {
      if (func_name.find(func->first) != std::string::npos)
        break;
    }

    // sanity check
    if (func == tf_func_registry.end()) {
      delete thread_ctx; // Prevent memory leak
      PIN_SetThreadData(func_tls_key, NULL, tid);
      return;
    }

    // CALL the post-hook callback if registered
    if (func->second.post) {
      func->second.post(&(thread_ctx->func_ctx));
    }

    delete thread_ctx;
  }

  PIN_SetThreadData(func_tls_key, NULL, tid);
}

using match_func = bool (*)(std::string rtn, std::string func);

static VOID
tf_instrument_rtn(
    RTN rtn, match_func cmp = [](std::string str1, std::string str2) {
      return str1.find(str2) != std::string::npos;
    }) {
  std::string func_name = RTN_Name(rtn);

  // invalid
  if (!RTN_Valid(rtn)) {
    fprintf(stderr, "[ERR] Attempted to instrument invalid routine: %s\n", func_name.c_str());
    return;
  } else {
    fprintf(stdout, "[INF] Instrumenting function: %s\n", func_name.c_str());
  }

  RTN_Open(rtn);

  // find the hook descriptor for this function
  hook_t hook = {nullptr, nullptr, nullptr};
  for (const auto &entry : tf_func_registry) {
    // important: partial matching
    // TODO: maybe sometimes aliases are completely different
    if (cmp(func_name, entry.first)) {
      hook = entry.second;
      break;
    }
  }

  if (hook.pre != nullptr) {
    RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)tf_pre_handler, IARG_THREAD_ID, IARG_CONTEXT,
                   IARG_ADDRINT, RTN_Address(rtn), IARG_RETURN_IP, IARG_UINT32, hook.sig->nargs,
                   // hand over both address and value
                   IARG_FUNCARG_ENTRYPOINT_REFERENCE, 0, IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
                   IARG_FUNCARG_ENTRYPOINT_REFERENCE, 1, IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
                   IARG_FUNCARG_ENTRYPOINT_REFERENCE, 2, IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
                   IARG_FUNCARG_ENTRYPOINT_REFERENCE, 3, IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
                   IARG_FUNCARG_ENTRYPOINT_REFERENCE, 4, IARG_FUNCARG_ENTRYPOINT_VALUE, 4,
                   IARG_FUNCARG_ENTRYPOINT_REFERENCE, 5, IARG_FUNCARG_ENTRYPOINT_VALUE, 5,
                   IARG_END);
  }

  if (hook.post != nullptr) {
    RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)tf_post_handler, IARG_THREAD_ID, IARG_CONTEXT,
                   IARG_ADDRINT, RTN_Address(rtn), IARG_FUNCRET_EXITPOINT_VALUE, IARG_END);
  }

  RTN_Close(rtn);
}

/*typedef struct {*/
/*  const char *lib;*/
/*  match_func cmp;*/
/*} probe_ctx_t;*/

static VOID
tf_instrument_img(IMG img, VOID *lib) {
  /*probe_ctx_t *ctx = (probe_ctx_t *)pc;*/

  // invalid
  if (!IMG_Valid(img)) {
    fprintf(stderr, "[ERR] Attempted to process invalid image\n");
    return;
  }

  // not the target library
  if (IMG_Name(img).find((const char *)lib) == std::string::npos) {
    return;
  }

  fprintf(stdout, "[INF] Processing image: %s\n", IMG_Name(img).c_str());
  for (const auto &kv : tf_func_registry) {
    std::string func_name = kv.first;

    RTN rtn = RTN_FindByName(img, func_name.c_str());
    ADDRINT addr = RTN_Address(rtn);
    for (SYM sym = IMG_RegsymHead(img); SYM_Valid(sym); sym = SYM_Next(sym)) {
      if (SYM_Address(sym) == addr) {
        // override the hooked name found in the lib
        // with the first funcion on the same address
        rtn = RTN_FindByName(img, SYM_Name(sym).c_str());
      }
    }

    // invalid symbol (e.g. inline)
    if (!RTN_Valid(rtn)) {
      continue;
    }

    // instrument
    tf_instrument_rtn(rtn);
  }
}

static VOID
fini(INT32 code, VOID *v) {
  logger.save_buffers();
  fprintf(stdout, "[INF] Application finished. Cleaning up function registry.\n");
  tf_func_registry.clear();
  tf_mem_die();
  libdft_die();
}

#endif // !TF_TOOLS_H
