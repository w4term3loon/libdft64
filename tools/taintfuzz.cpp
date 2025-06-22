#include "tf_tools.hpp"

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

  fprintf(stdout, "[INF] Starting program instrumentation...\n");
  PIN_StartProgram();

  return EXIT_SUCCESS;

err:
  fprintf(stderr, "[ERR] Tool initialization failed. Exiting.\n");
  return EXIT_FAILURE;
}

// TODO: instrument GOT/PLT or detect call ins for external lib call detection
// NOTE: GOT and PLT are for some reason completely empty in the test scenario
// TODO: hook libc
// TODO: try other libs
// TODO: parameter type info from signature in handlers or hooks
