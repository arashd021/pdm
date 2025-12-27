# PDM

This repository contains the artifacts for the paper "PROBE+DETECT+MITIGATE (PDM): Enabling Cloud Tenants to Self-Defend against Microarchitectural Attacks" submitted to USENIX Security 2026.


## Requirements
Tests were made on a fresh Ubuntu 24.04 installation as of December 2025.

`sudo apt update && sudo apt install -y build-essential libcapstone-dev libssl-dev libwolfssl-dev uthash-dev`


# Overview 

## Source code (`source` folder)

### `detection` folder

`PDM-detection.c`: Scheme3 probing with online ONNX-based ML inference.

`PDM-scheme3.c`: Scheme3 probing without ML inference.

`PDM-scheme3+.c`: standalone Scheme3+ probing without ML inference.

`example/fr` is an example victim application, a FLUSH+RELOAD attack, and how to integrate PDM for detection.

`example/fr-aes` is an example of FLUSH+RELOAD on OpenSSL AES and how to integrate PDM for detection.

`example/spectre-pht` is an example of Spectre-PHT and how to integrate PDM for detection.

These files correspond to the probing schemes (Section 3.1) and the detection engine (Section 3.2.2) of the paper and fulfill the paper’s commitment to release *probing and runtime inference source code*.

### `mitigation` folder
`PDM-encrypt.c` is the source code of the signal handler performing in-memory encryption through on-the-fly trampoline generation and inline binary rewriting.

`example/*` examples of cryptographic primitives for testing. 

These files correspond to the proposed in-memory encryption (Section 3.3) of the paper and fulfill the paper’s commitment to release the *in-memory encryption source code and pre-compiled binaries of applications with PDM integrated*.




## Datasets and Models (`datasets` folder)

The repository also includes datasets used in our experiments in both our local test-bed and on AWS Fargate, which include the normal activities of real-world applications, attack activities, natural noises from SPEC CPU 2017, artificial noises from memory stressors, and slow evasive attacks.

`fargate`: attack datasets collected on AWS Fargate container (presented in Table 2.b in Section 4.3.1).

`testbed`: attack datasets collected on our local testbed, including natural noises from co-resident SPEC CPU 2017  (presented in Table 2.1 in Section 4.3.1).

`noise`: attack datasets collected on our local testbed, including artificial noises from memory stressors (presented in Figure 9 in Section 4.5.2).

`testbed/evasive`: slow evasive attack datasets collected with different slowdown factors in our local testbed  (presented in Figure 10 in Section 4.5.3).

These files present the detection evaluation of the paper and fulfill the paper’s commitment to release * all the trained models and datasets used in our experiments, which include the normal activities of real-world applications, attack activities, natural noises from SPEC CPU 2017, and artificial noises from memory stressors, and slow evasive attacks*.



## Documentation
A complete compilation and usage instructions are provided inside each subdirectory under `README.md`.


## Licenses
The dataset files are released under the CC-BY-4.0 license. The source code presented in this repository is released under the MIT License.

## Disclaimer
This repository is provided for academic purposes only.

