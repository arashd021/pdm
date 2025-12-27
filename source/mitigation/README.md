### Mitigation

## Build


Mitigation in PDM is done through in-memory encryption of the secret(s). `PDM-encrypt.c` is a handler that can be compiled along with a program. At the program startup, it will first apply mprotect(PROT_NONE) to secret pages so that any access to them raises a segmentation fault (SIGSEGV). The handler then catches those segfaults, builds a trampoline for each one and replaces the secret access instruction with a jump to a trampoline. The trampoline function encrypts the secret before it is written in memory, and decrypts it when the program wants to read it.

Note that support for mitigation of already compiled programs at startup (with LD_PRELOAD), or runtime (through library injection) will be added in the future, similar to what is already implemented for PDM's probing and detection.

```
cd ~/PDM/source/mitigation/example
make
```

You can use the -DDEBUG flag during compilation to enable debugging mode and see generated trampolines.





## Usage 


We provide several examples of cryptographic primitives.

Examples of cryptographic primitives in `source/mitigation/examples` can be executed in two modes, selected by a command-line argument:

``` bash
./ecdh 1
./ecdh 2
```

> **Execution Modes**
> - **1**: Run the primitive without protection  
> - **2**: Run the primitive with mitigation enabled


For guaranteed reproducibility across machines, a ready-to-use Docker image with precompiled ELF 64-bit binaries is provided.
Run the container interactively:

``` bash
docker run --rm -it docker.io/pdmanon123/pdm-artifacts
```
