# libdft64 - Dynamic Data Flow Tracking with TaintFuzz for guided fuzzing

 > [!NOTE]
 > These code is modified from [AngoraFuzzer/libdft64](https://github.com/AngoraFuzzer/libdft64), and it is originally from [libdft](https://www.cs.columbia.edu/~vpk/research/libdft/).

A fast, reusable dynamic data flow tracking (DFT) framework for Intel Pin 3.x and 64-bit platforms, enhanced with TaintFuzz functionality for intelligent fuzzing based on taint analysis.

## Overview
libdft64 is a dynamic data flow tracking framework that provides comprehensive taint analysis capabilities for binary only targets. This enhanced version includes TaintFuzz functionality, which combines dynamic taint analysis at function level with fuzzing to identify critical input regions that affect program execution paths and potential vulnerabilities.

## Build
We suggest building the project from docker. This eliminates the bugs arising from the platform specificness of the Intel pintool. We also set up everything inside the image and hook up the pintool as intended by design.

```sh
# docker setup
make run

# build tool
make all
```

## Test

We have 2 main tests that we used during development:
```sh
cd tools
make stest
make dtest
```

`dtest` is a very simple test that makes sure that the instrumentation works and `stest` is a bit more complicated to check if the tool successfully identifies the potential issues in the binary.

## Installation

The docker container does this out of the box, but if someone wants to build on their machine:

- Download Intel Pin 3.x and set PIN_ROOT to Pin's directory.
- GCC compiler
- GNU Make
- Ubuntu 20.04 (tested) or compatible Linux distribution

```sh
PREFIX=/path-to-install ./install_pin.sh
export PIN_ROOT=/path/to/pin
```

## Library substitution
First of all, to generate the stubs for a new library, its header needs to be feeded to the `gen_sig.py` script:

```sh
./gen_sig.py /usr/include/stdlib.h -o test.inc
```

We tested the generation process on the following Linux libraries:
```sh
root@3cd5528b70be:/libdft# ./gen_sig.py /usr/include/string.h -o string.inc
Processing /usr/include/string.h...

Processed 51 unique functions:
  IO_SINK: 14
  IO_SRC: 3
  IO_SRC|IO_SINK: 31
  NO_IO: 3

Output written to string.inc
root@3cd5528b70be:/libdft# ./gen_sig.py /usr/include/stdio.h -o stdio.inc
Processing /usr/include/stdio.h...

Processed 84 unique functions:
  IO_SINK: 13
  IO_SRC: 1
  IO_SRC|IO_SINK: 66
  NO_IO: 4

Output written to stdio.inc
root@3cd5528b70be:/libdft# ./gen_sig.py /usr/include/time.h -o time.inc
Processing /usr/include/time.h...

Processed 30 unique functions:
  IO_SINK: 1
  IO_SRC|IO_SINK: 23
  NO_IO: 6

Output written to time.inc
root@3cd5528b70be:/libdft# ./gen_sig.py /usr/include/regex.h -o regex.inc
Processing /usr/include/regex.h...

Processed 6 unique functions:
  IO_SINK: 1
  IO_SRC|IO_SINK: 5

Output written to regex.inc
```

After the generation, the generated stubs need to be included in the `tf_gen.hpp` file:
```c
#define GENERATED_SIGS "tf_std_sig.inc"
```

and in the main `taintfuzz.cpp` tool the library needs to be registered:
```c
tf_register_all("test");
```

In the taintfuzz tool, the name that is registered in the main function is fuzzy searched in the section names.

## Instrumenting arbitrary binaries

The taintfuzz pintool can instrument any binary as long as the registered library is relevant. In this example we instrument a binary found in almost all Linux systems: `/bin/ls`. The following commands presume a running docker context after a successful `make run` command from the root directory:
```sh
cd tools
pin -t tools/obj-intel64/taintfuzz.so -- /bin/ls
```

The produced log verifies that the tool finds all `libc` functions (we registered `libc`) and do not contain any alarming events that would suggest that the binary piped tainted source data to sinks.

 > [!IMPORTANT]
 > Archive of the original Angora repository

## News
- Update Pin version: pin-3.20-98437-gf02b61307-gcc-linux
- Test in ubuntu 20.04

## Features

- Support Intel Pin 3.x
- Support Intel 64 bit platform
- Support basic SSE, AVX instructions.
- Use BDD data structure described in [Angora][3]'s paper.

## Limitation of our taint propagation rules
- Byte level
- Ignore implicit flows
- Ignore eflags registers
- Naive heuristics for parameter inference

## TODO
- [ ] ternary instructions
- [ ] performance optimization
- [ ] support more instructions
- [ ] test for each instruction
- [ ] rules for eflags registers
- [ ] FPU instructions

## Contributing guidance
As [TaintInduce](https://taintinduce.github.io/) mentioned, libdft exists the soundness and completeness probelm.
- The taint propagation rules may be wrong.
- It only supports the basic instructions, and there are many other instructions it need to support.

If you want to contribute to this, modify the instructions in `src/libdft_core.cpp`, and pull requests on github for us.

 > [!IMPORTANT]
 > Archive of the original libdtf repository
## Introduction
   Dynamic data flow tracking (DFT) deals with the tagging and tracking of
"interesting" data as they propagate during program execution. DFT has been
repeatedly implemented by a variety of tools for numerous purposes, including
protection from buffer overflow and cross-site scripting attacks, analysis of
legitimate and malicious software, detection and prevention of information
leaks, etc. libdft is a dynamic DFT framework that is at once fast, reusable,
and works with commodity software and hardware. It provides an API, which can
be used to deliver DFT-enabled tools that can be applied on unmodified binaries
running on common operating systems and hardware, thus facilitating research
and rapid prototyping.


## Installation & Usage
   libdft relies on [Intel Pin](http://www.pintool.org), which is a dynamic binary
instrumentation (DBI) framework from Intel. In order to install libdft you first
need a working copy on the latest Pin build, as well as the essential build
tools for GNU/Linux (i.e., GCC, GNU Make, etc). After downloading and installing
Intel Pin please follow the [libdft installation instructions](INSTALL.md).

### Tools
   libdft is designed to facilitate the creation of "Pin tools" that employ
dynamic DFT. As the name implies, libdft is also a shared library, which can be 
used to transparently perform DFT on binaries. Additionally, it provides an API 
that enables tool authors to adjust the applied DFT by specifying data sources
and sinks, and customize the tag propagation policy. We have included three
simple Pin tools inside the [`tools`](tools) subdirectory to aid the development of
DFT-powered Pintools:

  * [`nullpin`](tools/nullpin.cpp) is essentially a null tool
    that runs a process using Pin without any form of instrumentation or analysis.
    This tool can be used to measure the overhead imposed by Pin's runtime
    environment.
  * [`libdft`](tools/libdft.cpp) uses libdft to apply DFT on the application being
    executed, but does not use any of the API functions to define data sources and
    sinks (i.e., it does not customize the applied DFT).
    This tool can be used to evaluate the overhead imposed by libdft.
  * [`track`](tools/track.cpp) is an example tool that uses the API
    of libdft, and serves as template for future meta-tools.
    In particular, it implements a dynamic taint analysis (DTA)
    platform by transparently utilizing DFT in unmodified x86 Linux binaries.
    The sources are arguemnts in `__libdft_set_taint`, and sinks are arguments 
    in `__libdft_get_taint` and `__libdft_getval_taint`. libdft64 is also used in Angora
    for taint tracking. You can reading code at `https://github.com/AngoraFuzzer/Angora/tree/master/pin_mode`
    as example.

   DTA operates by tagging all data coming from the network as "tainted",
tracking their propagation, and alerting the user when they are used in a way
that could compromise his system. In this case, the network is the source of
"interesting" data, while instructions that are used to control a program's flow
are the sinks. For the x86 architecture, these are jumps and function calls with
non-immediate operands, as well as function returns. Oftentimes, attackers are
able to manipulate the operands of such instructions by abusing various types of
software memory errors such as buffer overflows, format string vulnerabilities, 
dangling pointers, etc. They can then seize control of a program by redirecting 
execution to existing code (e.g., return-to-libc, ROP), or their own injected
instructions. libdft-dta checks if tainted data are used in indirect control
transfers, and if so, it halts execution with an informative message containing 
the offending instruction and the contents of the instruction pointer EIP.

### Usage
   After building both libdft and the accompanying tools (i.e., `nullpin`,
`libdft`, and `track`), you can apply them directly in unmodified x86
Linux binaries as follows (assuming that you have added Pin's location to
your `PATH`, and installed libdft in your home directory):

```shell
pin -t obj-intel64/track.so -- obj-intel64/mini_test.exe  cur_input
```

#### Arguments processed by Pin
  * `-follow_execv`: Instructs Pin to also instrument all processes spawned
     using the `exec(3)` class system calls by the program.
  * `-t`: Specifies the Pin tool to be used.


## Research
   Following are some publications that rely on libdft:

  * **[libdft: Practical Dynamic Data Flow Tracking for Commodity Systems][1].**
    *Vasileios P. Kemerlis, Georgios Portokalidis, Kangkook Jee, and Angelos D. Keromytis.*
    In Proceedings of the *8th ACM SIGPLAN/SIGOPS International Conference on Virtual Execution Environments (VEE)*. March 2012, London, UK.
  * **[A General Approach for Efficiently Accelerating Software-based Dynamic Data Flow Tracking on Commodity Hardware][2].**
    *Kangkook Jee, Georgios Portokalidis, Vasileios P. Kemerlis, Soumyadeep Ghosh, David I. August, and Angelos D. Keromytis.*
    In Proceedings of the *19th Internet Society (ISOC) Symposium on Network and Distributed System Security (NDSS)*. February 2012, San Diego, CA.

  * **[Angora: Efficient Fuzzing by Principled Search][3]** In Proceedings of the *IEEE Symposium on Security and Privacy (SP). San Francisco*, CA, May 2018.

  * **[VUzzer: Application-aware Evolutionary Fuzzing][4]** In Proceedings of the *Internet Society (ISOC) Symposium on Network and Distributed System Security (NDSS)*. Feb 2017.

[1]: http://nsl.cs.columbia.edu/papers/2012/libdft.vee12.pdf
[2]: http://nsl.cs.columbia.edu/papers/2012/tfa.ndss12.pdf
[3]: https://arxiv.org/abs/1803.01307
[4]: https://www.cs.vu.nl/~herbertb/download/papers/vuzzer_ndss17.pdf

