#ifndef __FUNCTION_DESC_H__
#define __FUNCTION_DESC_H__

#include "libdft_api.h"

//#define SYSCALL_MAX 334 + 1//__NR_sched_getattr + 1 /* max syscall number */
#define FUNCTION_MAX 2

enum {
    __RTN_free
};

/* function call descriptor */
typedef struct {
  size_t nargs;                           /* number of arguments */
  size_t save_args;                       /* flag; save arguments */
  size_t retval_args;                     /* flag; returns value in arguments */
  size_t map_args[SYSCALL_ARG_NUM];       /* arguments map */
  void (*pre)(THREADID, function_ctx_t *); /* pre-syscall callback */
  void (*post)(THREADID, function_ctx_t *); /* post-syscall callback */
} function_desc_t;

/* function API */
int function_set_pre(function_desc_t *, void (*)(THREADID, function_ctx_t *));
int function_clr_pre(function_desc_t *);
int function_set_post(function_desc_t *, void (*)(THREADID, function_ctx_t *));
int function_clr_post(function_desc_t *);

#endif /* __FUNCTION_DESC_H__ */