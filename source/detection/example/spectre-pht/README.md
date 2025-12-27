# Spectre-pht Example

Proof of concept code for the Spectre CPU exploit.

Based on the implementation provided by Crozone at: https://github.com/crozone/SpectrePoC.

Originated from the example code provided in the "Spectre Attacks: Exploiting Speculative Execution" paper: https://spectreattack.com/spectre.pdf.

## Building

The project can be built with GNU Make and GCC.

`make`

The output binary is `./spectre.out`.


## Executing

To run spectre with a default cache hit threshold of 80, and the secret example string "The Magic Words are Squeamish Ossifrage," as the target, run `./spectre.out` with no command line arguments.

    ~/PDM/source/detection/example/spectre-pht$ ./spectre.out
    The virtual address of 'secret' is: 0x555555556008
    Length of the string in secret: 40 characters

To enable the attack:

`kill -SIGUSR1 $(pidof spectre.out)`

To disable the attack

`kill -SIGUSR2 $(pidof spectre.out)`

## Detection with PDM

Enable the flag `#define USE_FIXED_START_ADDR` in PDM's probing codes, and update PDM's probing range to include the secret address printed by `spectre.out` and recompile. For instance:

    #define USE_FIXED_START_ADDR
    #define START_ADDR 0x555555556008
    #define SIZE 128

Inject PDM at startup using LD_PRELOAD:

`LD_PRELOAD=../../PDM-detection.so taskset -c 0 ./spectre.out`

Running the attack causes a spike in the L1hit2 ratio.
