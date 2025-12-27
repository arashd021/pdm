### Probing and Detection


## ONNXRuntime
ONNXRuntime is required to compile PDM's detection models. This allows for better performance at inference.
To install ONNXRuntime (v1.22):
```
cd ~
wget https://github.com/microsoft/onnxruntime/releases/download/v1.22.0/onnxruntime-linux-x64-1.22.0.tgz
tar -xvf onnxruntime-linux-x64-1.22.0.tgz
```



## Build

```
cd ~/PDM/source/detection
make
```
This builds `PDM-detection.so` (Scheme3 probing with online ONNX-based ML inference), `PDM-scheme3.so` (standalone Scheme3 probing without ML inference), and `PDM-scheme3+.so` (standalone Scheme3+ probing without ML inference) that can be loaded into a victim program to protect it (see Usage).

## Threshold Calibration

This repository contains a calibration tool to identify the thresholds required by PDM for different layers of cache. This code is based on the calibration implementation provided by Daniel Gruss (https://github.com/IAIK/flush_flush) but slightly modified to provide 3 distinct thresholds for different cache levels. To find the thresholds, simply run:

```
./calibration
```

And then update the thresholds in PDM's probing codes to match your system's thresholds.

## Usage 

There are currently two ways of loading PDM's probing and detection modules, as follows.

- LD_PRELOAD:
One can load PDM at the start of a new process using LD_PRELOAD.

For instance:
```
cd example/fr
sudo taskset -c 0 sh -c 'LD_PRELOAD=../PDM-detection.so ./victim'
```

- Library Injection:
If one wishes to apply PDM's detection to an already running process, then library injection is suitable.

First, install the runtime .so library injection tool (https://github.com/kubo/injector):
```
cd injector
make
```

Next, run the example victim application:
```
cd example/fr
sudo ./victim
```

Then, inject the shared library into the victim at runtime:
```
cd detection
sudo ./injector/cmd/injector -p $(pidof victim) PDM-detection.so
```

More examples on how to integrate PDM into applications and test it against attacks are given in the `example` directory.
