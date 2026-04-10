# Flush and Reload Cache Side Channel Attack

Based on the implementation provided by Daniel Gruss: https://github.com/isec-tugraz/flush_flush

This repository is an implementation of a flush-reload side channel attack on OpenSSL's AES-128's t-table implementation.

## OpenSSL Installation

This example requires a self-compiled version of OpenSSL to enable its T-Table-based AES implementation.

```
$ wget https://www.openssl.org/source/openssl-1.1.0f.tar.gz
$ tar -xvf openssl-1.1.0f.tar.gz
$ cd openssl-1.1.0f
# Fix Perl compatibility in all files
$ grep -rl "qw/glob/" . | xargs sed -i 's|qw/glob/|qw/:globally/|g'
# Configure
$ ./config -d shared no-asm no-hw --prefix=/usr/local/ssl_vuln
# Build and Install
$ sudo make
$ sudo make install_sw
```

## Finding T-table Addresses

```
$ nm nm /usr/local/ssl_vuln/lib/libcrypto.so | grep Te
```

Update them in spy.cpp 

## Building

The command for compiling the spy.c file is:

```
$ g++ spy.cpp -o spy -I/usr/local/ssl_vuln/include -L/usr/local/ssl_vuln/lib/ -lcrypto
$ gcc aes-workload.c -o aes-workload -I/usr/local/ssl_vuln/include -L/usr/local/ssl_vuln/lib/ -lcrypto
```

### Detection with PDM

Since we have installed OpenSSL in a local directory instead of a system directory, we need to tell the linker to use the
appropriate version of OpenSSL. To do this, type in the terminal:

```
$ export LD_LIBRARY_PATH=/usr/local/ssl_vuln/lib:$LD_LIBRARY_PATH
```

PDM can be configured to use fixed address ranges (e.g., AES T-tables addresses). T-table addresses can simply be found by running the binary (keep  the process running so addresses do not change across runs due to ASLR):

```

$ taskset -c 0 ./spy

Probing address (Te0): 0x7ffff6fdfc00
Probing address (Te1): 0x7ffff6fdf800
Probing address (Te2): 0x7ffff6fdf400
Probing address (Te3): 0x7ffff6fdf000
```

Next, enable the flag `#define USE_FIXED_START_ADDR` in `pdm/source/detection/constants.h`, and update PDM's probing range to include the T-table addresses. For instance:

```
    #define USE_FIXED_START_ADDR
    #define START_ADDR 0x7ffff6fdf000
    #define SIZE 3072
```

Finally, recompile PDM's detection:

```
$ cd pdm/source/detection
$ make clean
$ make
```

## Executing

Run the spy process, and it should print the T-table virtual addresses like below:

```
# Terminal 1: spy already running (printed probed Te* addresses)
```

The AES workload can be separately adjusted:

```
# Terminal 2: start continuous AES encryptions (victim workload)
$ export LD_LIBRARY_PATH=/usr/local/ssl_vuln/lib:$LD_LIBRARY_PATH
$ ./aes-workload 1
```


Use the runtime ptrace injection to inject PDM's shared library into the application to initiate monitoring and detection:

```
# Terminal 3: inject PDM detection into the spy process
$ cd pdm/source/detection/
$ sudo ./injector/cmd/injector -p $(pidof spy) ../PDM-detection.so
 ```

After injection, PDM prints the multivariate time-series and the ONNX model output (in Terminal 1).

Next, in the same terminal, to enable/disable the attack:

```
# Terminal 3: Toggle attack (in the spy process)
$ kill -SIGUSR1 $(pidof spy) # enable attack
$ kill -SIGUSR2 $(pidof spy) # disable attack
```

When the attack is enabled (SIGUSR1), the model output should shift compared to the benign phase (SIGUSR2), matching the eviction effect reported in the paper.