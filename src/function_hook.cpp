#include "function_desc.h"
#include "function_hook.h"
#include "pin.H"

#if defined(TARGET_MAC)
#define MALLOC "_malloc"
#define FREE "_free"
#else
#define MALLOC "malloc"
#define FREE "free"
#endif

ADDRINT address = 0;

static void pre_free_hook(CHAR* name, ADDRINT addr) {
    printf("free addr: %lx\n", addr);
    address = addr;
    //tagmap_setn(buf, nr, freed_tag);
}

static void post_free_hook(ADDRINT ret) {
    if (ret < 0) return;
}

static void free_hook(IMG img) {
    // Find the free() function.
    RTN freeRtn = RTN_FindByName(img, FREE);
    if (RTN_Valid(freeRtn))
    {
        RTN_Open(freeRtn);
        // Instrument free() to print the input argument value.
        RTN_InsertCall(freeRtn, IPOINT_BEFORE, (AFUNPTR)pre_free_hook, IARG_ADDRINT, FREE, IARG_FUNCARG_ENTRYPOINT_VALUE, 0, IARG_END);
        RTN_InsertCall(freeRtn, IPOINT_AFTER, (AFUNPTR)post_free_hook, IARG_FUNCRET_EXITPOINT_VALUE, IARG_END);
        RTN_Close(freeRtn);
    }
    
}

static void pre_unknown_api(ADDRINT arg0){
    printf("arg0: %lx\n", arg0);
}

ADDRINT low_address;
ADDRINT high_address;

VOID Image(IMG img, VOID* v)
{
    if (IMG_IsMainExecutable(img)) {
        low_address = IMG_LowAddress(img);
        high_address = IMG_HighAddress(img);
        return;
    }
    free_hook(img);
}

VOID Instruction(INS ins, VOID* v)
{
    if(INS_IsCall(ins)){
        ADDRINT ins_addr = INS_Address(ins);
        if(ins_addr >= low_address && ins_addr <= high_address){
            INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)pre_unknown_api, IARG_FUNCARG_CALLSITE_VALUE, 0, IARG_END);
        }
    }
}


void hook_file_function(){
    IMG_AddInstrumentFunction(Image, 0);
    INS_AddInstrumentFunction(Instruction, 0);
}