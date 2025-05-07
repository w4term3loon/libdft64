#include "function_desc.h"
#include "branch_pred.h"

//static tag_traits<tag_t>::type freed_tag = 2; //TODO: set a enum for tag type

//static void post_free_hook(THREADID tid, function_ctx_t *ctx);



function_desc_t function_desc[FUNCTION_MAX] = {
    //{3, 1, 0, {0, 0, 0, 0, 0, 0}, NULL, post_scanf_hook} how to handle unset number parameter functions
    //__RTN_free
    {1, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL},
};

int function_set_post(function_desc_t *desc,
    void (*post)(THREADID, function_ctx_t *)) {
/* sanity checks */
if (unlikely((desc == NULL) | (post == NULL)))
/* return with failure */
return 1;

/* update the post-syscall callback */
desc->post = post;

/* set the save arguments flag */
desc->save_args = 1;

/* success */
return 0;
}