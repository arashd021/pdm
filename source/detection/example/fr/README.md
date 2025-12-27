# Simple FLUSH+RELOAD Example

## Building

Build the project with:

`make`

The output binaries are `./victim` and `./F+R`.

## Executing and Detection with PDM

To run the victim binary with PDM integrate run:

`sudo LD_PRELOAD=../../PDM-detection.so taskset -c 0 ./victim`

By enabling the flag `#define USE_PROC_MAPS` in PDM's probing codes, the probing range will be automatically extracted using the function `get_shared_secret_address(getpid());`.

You should see benign datapoints like:

`14:55:43.967 l1hit: 100.00 ** l3hit:   0.00  ** miss:   0.00 ** bigmiss:   0.00 =====  l1hit2:   0.00 ** l3hit2:   0.00 ** miss2: 100.00 ** bigmiss2:   0.00 | Model Output: 0.000000 ** batch_offset: 2560 `

Where the L1hit ratio is 100% and the model output is 0.

Next, run the attack:

`F+R`

You should see a decrease in L1 hit ratio and an increase in model output:

`14:57:37.019 l1hit:  25.00 ** l3hit:   0.00  ** miss:  62.50 ** bigmiss:  12.50 =====  l1hit2:   0.00 ** l3hit2:   0.00 ** miss2: 100.00 ** bigmiss2:   0.00 | Model Output: 0.800035 ** batch_offset: 0`