# C Fuzzer for File Mutations

This C program is a fuzzer targeting the **exif** tool, designed to test the tool's resilience to invalid or unexpected inputs by repeatedly mutating test case files (JPEG images). The fuzzer generates a set of mutated files and spawns child processes that run the **exif** tool on these files. Key features:

- **File Mutation**: Mutates test cases by flipping bits or inserting "magic" values.
- **Fault Detection**: Captures child process crashes and records backtraces of faults for further analysis.
- **Optimization**: Uses `vfork()` to spawn child processes and connects output to `/dev/null`.
- **Test Cases**: Reads and stores test cases from a `testcases` directory and continuously mutates them.

## Key Parameters:
- **TARGETTOFUZZ**: Defines the tool being fuzzed (e.g., `exif`).
- **MAX_FUZZ_ITERATIONS**: Maximum number of fuzzing iterations (default: 1,000,000).
- **FLIP_PERCENT**: Probability of bit flipping during file mutation.
- **Fault Handling**: Captures signals like `SIGSEGV` and logs the stack trace.

The program identifies useful test cases by checking for unique crash signatures, discarding redundant or non-crashing mutations, and saving new fault-inducing test cases in a `faults` directory.
