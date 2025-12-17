# PDM

This repository contains the artifacts for the paper "PROBE+DETECT+MITIGATE (PDM): Enabling Cloud Tenants to Self-Defend against Microarchitectural Attacks" submitted to USENIX Security 2026.




## Requirements
Tests were made on a fresh Ubuntu 24.04 installation as of December 2025.

`sudo apt update && sudo apt install -y build-essential libcapstone-dev libssl-dev libwolfssl-dev uthash-dev`

### ONNXRuntime
ONNXRuntime is required to compile PDM's detection models. This allows for better performance at inference.
To install ONNXRuntime (v1.22):
```
cd ~
wget https://github.com/microsoft/onnxruntime/releases/download/v1.22.0/onnxruntime-linux-x64-1.22.0.tgz
tar -xvf onnxruntime-linux-x64-1.22.0.tgz
```






## Build


### Detection
```
cd ~/PDM/source/detection
make
```
This builds `PDM-detection.so` (Scheme3 probing with online ONNX-based ML inference) and `PDM-scheme3+.so` (standalone Scheme3+ probing without ML inference) that can be loaded into a victim program to protect it (see Usage).


### Mitigation

Mitigation in PDM is done through in-memory encryption of the secret(s). `PDM-encrypt.c` is a handler that can be compiled along with a program. At the program startup, it will first apply mprotect(PROT_NONE) to secret pages so that any access to them raises a segmentation fault (SIGSEGV). The handler then catches those segfaults, builds a trampoline for each one and replaces the secret access instruction with a jump to a trampoline. The trampoline function encrypts the secret before it is written in memory, and decrypts it when the program wants to read it.

Note that support for mitigation of already compiled programs (with LD_PRELOAD), or already running program (through library injection) will be added in the future.

```
cd ~/PDM/source/mitigation/example
make
```
You can use the -DDEBUG flag during compilation to enable debugging mode and see generated trampolines.





## Usage 


### Detection
There are currently two ways of loading PDM's probing and detection modules, as follows.

- LD_PRELOAD:
One can load PDM at the start of a new process using LD_PRELOAD.

For instance:
```
cd example
sudo taskset -c 0 sh -c 'LD_PRELOAD=../PDM-detection.so ./victim'
```

- Library Injection:
If one wishes to apply PDM to an already existing task, then library injection is suitable:

First install the runtime .so library injection tool:
```
git clone https://github.com/kubo/injector
cd injector
make
```

Next, run the example victim application:
```
cd example
sudo ./victim
```

Then, inject the shared library to the victim at runtime:
```
sudo ./injector -p `pgrep victim` detection/PDM-detection.so
```


### Mitigation

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
docker run --rm -it pdmanon123/pdm-artifacts
```


## Dataset and ML Model Training

We provide some datasets and models trained on different platforms and applications in the `datasets` folder.
Each dataset includes ML model weights (`.pth` and `.pkl` files) and Jupyter notebooks (`.ipynb` files).

The detection datasets and model artifacts were tested with Python 3.9+. You will need the following Python packages:

pandas, numpy, torch, scikit-learn, joblib

You can install them with:

``` bash
pip install -r requirements.txt
```

Next, you can open the corresponding jupyter notebook for each environment (testbed or AWS Fargate) and run inference on each dataset.


## Licenses
The dataset files are released under the CC-BY-4.0 license. The source code presented in this repository is released under the MIT License.

## Disclaimer
This repository is provided for academic purposes only.

