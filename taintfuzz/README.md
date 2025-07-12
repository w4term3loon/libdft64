# Build

Before building the fuzzer, you need to change the path of libafl in *Cargo.toml*. After that, the build command is `cargo build`

# Run

The command to run fuzzer is `/path/to/taintfuzz -i /path/to/input -o /path/to/output -t /path/to/taintfuzz.so -- program parameters`

*Important*: Before run the fuzzer, you should set `export PIN_ROOT=/path/to/pin`. Besides, the output file must be empty

If the parameter contains input file, the filename should be @@. 

# Errors

Due to the HashMatch, if there is no match string in original input and tainted variables. It will crash. Please rerun fuzzer. It would be fixed in later.

# Key metrics

<img width="1831" height="124" alt="image" src="https://github.com/user-attachments/assets/eb15143a-a474-44af-8702-2dd90c2e4346" />

- runtime: the duration of fuzzing
- clients: how many process is running
- corpus: the number of corpus
- objectives: the number of crash
- executions: the number of execution
- exec/sec: the speed of fuzzing
- stability: the similarity of current execution and before
- edges: coverage of execution
