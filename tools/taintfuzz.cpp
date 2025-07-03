#include "tf_tools.hpp"

// --- LibC Specific Overrides ---
ins_desc_t ins_desc[XED_ICLASS_LAST];

void
trace_uaf(INS ins);// actual trace for logging

void
trace_uaf_start() {// a start function to implement trace uaf
  xed_iclass_enum_t ins_indx;
  ins_indx = XED_ICLASS_MOV;
  if (unlikely(ins_desc[ins_indx].pre == NULL))
    ins_desc[ins_indx].pre = trace_uaf;
}

void
trace_uaf_stop() {// a stop function to stop trace
  xed_iclass_enum_t ins_indx;
  ins_indx = XED_ICLASS_MOV;
  if (unlikely(ins_desc[ins_indx].pre == trace_uaf))
    ins_desc[ins_indx].pre = NULL;
}

void
uaf(ADDRINT dst) {// check taint and log
  // printf("memory: %lx\n", dst);
  if (tag_uaf_getb(dst)) {
    logger.store_ins(TT_UAF, dst);
    trace_uaf_stop();
  }
}

void
trace_uaf(INS ins) {// call uaf to trace
  if (INS_OperandIsMemory(ins, 0)) {
    INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)uaf, IARG_FAST_ANALYSIS_CALL, IARG_MEMORYWRITE_EA,
                   IARG_END);
  }
}

static void trace_cmp(INS ins);

static void
trace_cmp_stop(){// a stop function for stopping trace cmp
  xed_iclass_enum_t ins_indx;

  ins_indx = XED_ICLASS_CMP;

  if (unlikely(ins_desc[ins_indx].pre == trace_cmp))
    ins_desc[ins_indx].pre = NULL;
}

static void
trace_cmp(INS ins){//log cmp instruction address
  if (INS_OperandIsReg(ins, 0) && INS_OperandIsImmediate(ins, 1)) {
    ADDRINT addr = INS_Address(ins);
    logger.store_cmp_ins(TT_CMP, addr);
  }
  trace_cmp_stop();
}

static void
trace_cmp_start(){// start trace cmp
  xed_iclass_enum_t ins_indx;

  ins_indx = XED_ICLASS_CMP;

  if (unlikely(ins_desc[ins_indx].pre == NULL))
    ins_desc[ins_indx].pre = trace_cmp;
}

static void
trace_ret(INS ins) {// after return, stop tracing uaf to reduce overload
  trace_uaf_stop();
}

static void
trace_ret_start(){// start tracing ret
  xed_iclass_enum_t ins_indx;

  ins_indx = XED_ICLASS_RET_NEAR;

  if (unlikely(ins_desc[ins_indx].pre == NULL))
    ins_desc[ins_indx].pre = trace_ret;
}

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

  /*probe_ctx_t pc = {"libc", (match_func)[](std::string str1, std::string str2) {*/
  /*                    return (str1.find(str2) != std::string::npos);*/
  /*                  }};*/

  PIN_InitSymbols();
  if (PIN_Init(argc, argv)) {
    fprintf(stderr, "[ERR] PIN_Init failed: %s\n", PIN_ToolFullPath());
    goto err;
  }

  func_tls_key = PIN_CreateThreadDataKey(NULL); // Pass destructor if needed
  if (func_tls_key == INVALID_TLS_KEY) {
    fprintf(stderr, "[ERR] Cannot allocate TLS key.\n");
    goto err;
  }

  if (libdft_init() != 0) {
    fprintf(stderr, "[ERR] Failed to initialize libdft.\n");
    goto err;
  }

  // init mem
  tf_mem_init();

  // register all generic hooks
  tf_register_all();

  // register hooks manually
  tf_override_func("free", pre_free_hook, post_free_hook);

  IMG_AddInstrumentFunction(tf_instrument_img, (VOID *)"libc");

  // register Fini function to be called when the application exits
  PIN_AddFiniFunction(fini, 0);

  // for uaf detection, we check each time ret, if there is uaf tracing, stop it. (can be improved)
  trace_ret_start();

  // trace cmp to get mutation target
  trace_cmp_start();

  fprintf(stdout, "[INF] Starting program instrumentation...\n");
  PIN_StartProgram();

  return EXIT_SUCCESS;

err:
  fprintf(stderr, "[ERR] Tool initialization failed. Exiting.\n");
  return EXIT_FAILURE;
}

