#ifndef LOGGER_H
#define LOGGER_H

#include "libdft_api.h"
#include <set>
#include <stdint.h>

typedef uint32_t u32;
typedef uint64_t u64;

#define TRACK_COND_OUTPUT_VAR "ANGORA_TRACK_OUTPUT"

#define BUF_LEN (2 << 16)

typedef enum {
  TT_EXEC = 0,        //< command injection.
} taint_type_t;

struct CondStmt {
  u32 taint_type;
  u32 size;
};

class LogBuf {
private:
  char *buffer;
  size_t cap;
  size_t len;

public:
  void push_bytes(char *bytes, std::size_t size) {
    if (size > 0 && bytes) {
      size_t next = len + size;
      if (next > cap) {
        cap *= 2;
        buffer = (char *)realloc(buffer, cap);
      }
      memcpy(buffer + len, bytes, size);
      len = len + size;
    }
  };

  void write_file(FILE *out_f) {
    if (!out_f || len == 0)
      return;
    int nr = fwrite(buffer, len, 1, out_f);
    if (nr < 1) {
      fprintf(stderr, "fail to write file %d %lu\n", nr, len);
      exit(1);
    }
  };

  LogBuf() {
    cap = BUF_LEN;
    buffer = (char *)malloc(cap);
    len = 0;
  };
  ~LogBuf() { free(buffer); }
};

class Logger {
private:
  u32 num_exec;
  LogBuf exec_buf;
  std::map<u64, u32> order_map;


public:
  Logger(){};
  ~Logger(){};
  void store(taint_type_t type, tf_hook_ctx_t *ctx){
    //fprintf(stdout, "[LOGGER] start store\n");
    if (type == TT_EXEC){// command injection 
      ADDRINT hash = ctx->address;
      u32 size = 0;
      for (int i = 0; i < (int)ctx->args.size(); i++){
        // hash ^= ctx->args[i];// identify unique
        size += strlen((char *)ctx->args[i]);
        //fprintf(stdout, "args size: %d\n", size);
      }
      char args[size];
      memset(args, 0, size);
      if (order_map.count(hash) == 0 && size > 0) {
        for (int i = 0; i< (int)ctx->args.size(); i++){
          strcat(args,(char *)ctx->args[i]);
        }
        fprintf(stdout, "taint_arg: %s\n", args);
        order_map.insert(std::pair<u64, u32>(hash, 1));
        //exec_buf.push_bytes((char *)&type, 4);// insert struct size, args
        exec_buf.push_bytes((char *)&size, 4);
        exec_buf.push_bytes(args, size);
        num_exec += 1;
      }
    }
  }

  void save_buffers() {
    FILE *out_f = NULL;
    char *track_file = getenv(TRACK_COND_OUTPUT_VAR);
    if (track_file) {
      out_f = fopen(track_file, "w");
    } else {
      out_f = fopen("track.out", "w");
    }

    fwrite(&num_exec, 4, 1, out_f);
    exec_buf.write_file(out_f);

    if (out_f) {
      fclose(out_f);
      out_f = NULL;
    }
  }
};
#endif