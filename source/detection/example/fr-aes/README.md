# Flush and Reload Cache Side Channel Attack

Based on the implementation provided by Daniel Gruss: https://github.com/isec-tugraz/flush_flush

This repository is an implementation of a flush-reload side channel attack on OpenSSL's AES-128's t-table implementation.

## OpenSSL Installation

This example requires a self-compiled version of OpenSSL to enable its T-Table-based AES implementation.

 wget https://www.openssl.org/source/openssl-1.1.0f.tar.gz
 tar -xvf openssl-1.1.0f.tar.gz
 cd openssl-1.1.0f
 ./config -d shared no-asm no-hw --prefix=/usr/local/ssl_vuln
 sudo make
 sudo make install_sw


## Finding T-table Addresses

 nm nm /usr/local/ssl_vuln/lib/libcrypto.so | grep Te

Update them in spy.cpp 

## Building

Since we have installed OpenSSL in a local directory instead of a system directory, we need to tell the linker to use the
appropriate version of OpenSSL. To do this, type in the terminal:

 export LDFLAGS="-L/usr/local/ssl_vuln/lib"
 export CPPFLAGS="-I/usr/local/ssl_vuln/include"
 export LD_LIBRARY_PATH=/usr/local/ssl_vuln/lib:$LD_LIBRARY_PATH


The command for compiling the spy.c file is:

 g++ spy.cpp -o spy -I/usr/local/ssl_vuln/include -L/usr/local/ssl_vuln/lib/ -lcrypto
    
## Executing

Run the binary, and it should print the T-table virtual addresses like below:

 ./spy
 Probing address (Te0): 0x7ffff6fdfc00
 Probing address (Te1): 0x7ffff6fdf800
 Probing address (Te2): 0x7ffff6fdf400
 Probing address (Te3): 0x7ffff6fdf000

To enable/disable the attack:

kill -SIGUSR1 $(pidof spy) # enable attack
kill -SIGUSR2 $(pidof spy) # disable attack

The AES workload can be separately adjusted using the 'aes-workload.c' file.

    gcc aes-workload.c -o aes-workload
    ./aes-workload

## Detection with PDM

Next, we enables the flag `#define USE_FIXED_START_ADDR` in PDM's probing codes, and update PDM's probing range to include the T-table addresses and recompile. For instance:

    #define USE_FIXED_START_ADDR
    #define START_ADDR 0x7ffff6fdf000
    #define SIZE 3072

We then use the runtime ptrace injection to inject PDM's shared library into the application to initiate monitoring and detection:

 cd detection
 sudo ./injector/cmd/injector -p $(pidof spy) PDM-detection.so