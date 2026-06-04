# DGTOTP-TLS Project
## Overview
This project implements a DGTOTP-TLS authentication system that integrates DGTOTP-based verification with TLS communication. It provides three runtime components: a client, a server, and a verifier.

## System Requirements
Operating System: Linux (tested on Ubuntu 18.04.6 LTS)

CMake: Version 3.10 or higher

C++ Compiler: Supporting C++11 standard

## Dependencies
The project depends on the following libraries:

**OpenSSL** – For TLS/SSL functionality and cryptographic operations.

**GMP** (GNU Multiple Precision Arithmetic Library) – For high-precision arithmetic.

**Crypto++** – For additional cryptographic algorithms.

## Installation & Setup
Step 1: Install Dependencies
```bash
# Debian/Ubuntu
sudo apt-get update
sudo apt-get install libssl-dev libgmp-dev libcrypto++-dev

# Fedora/RHEL/CentOS
sudo dnf install openssl-devel gmp-devel cryptopp-devel
```

Step 2: Clone the Project
```bash
# Clone the repository (if applicable)
git clone <repository-url>
cd <project-directory>
```

Step 3: Build and Generate Certificates
```bash
chmod +x setup.sh
./setup.sh
```

## How to Run
After running `setup.sh`, the TLS executables built from `tls/client.cpp`,
`tls/server.cpp`, and `tls/verifier.cpp` are available in the `build/`
directory. Start them in the following order:

```bash
# Terminal 1: start the server
cd build
./server

# Terminal 2: start the verifier
cd build
./verifier

# Terminal 3: run the client
cd build
./client
```

Please start the server and verifier before running the client.

## How to Benchmark

Run `setup.sh` first so that all benchmark targets are built and the required
TLS certificates are generated in the `build/` directory.

```bash
chmod +x setup.sh
./setup.sh
```

### DGTOTP Benchmark
The `benchmark` executable measures the core DGTOTP and cryptographic
operations implemented in `test/benchmark.cpp`.

```bash
cd build
./benchmark
```

This benchmark prints timing and CPU-cycle statistics to the terminal and saves
raw cycle samples to `build/benchmark_dgtotp.txt`.

### TLS Handshake Benchmark
The `tls_benchmark` executable measures TLS 1.3 handshake performance for both
one-way authentication and two-way mutual authentication, using the benchmark
logic in `test/tls_benchmark.cpp`.

```bash
cd build
./tls_benchmark
```

The TLS benchmark runs local background server threads and uses ports `4440`
for one-way authentication and `4441` for two-way authentication. Make sure
these ports are free before running it. Run this command from `build/` because
the benchmark loads `ca.crt`, `server.crt`, `server.key`, `verifier.crt`, and
`verifier.key` from the current directory.

## Project Structure
```text
DGTOTP-TLS-main/
├─ inc/            #Header files (if not shown, assumed to exist).

├─ src/            #Contains the core source files for cryptographic and utility functions.

├─ tls/            #Contains TLS-specific client, server, and verifier implementations.

├─ test/          # Benchmark and test source files.

├─ setup.sh       # Build script and certificate generation.

├─ CMakeLists.txt  #CMake build configuration.
```