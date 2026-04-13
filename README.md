# DGTOTP-TLS Project
## Overview
This project implements a DGTOTP-TLS system for secure authentication and verification using cryptographic libraries and TLS communication. It includes three executable components: a client, a server, and a verifier.

## System Requirements
Operating System: Linux (tested on x86_64 Ubuntu)

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

Step 2: Clone and Build the Project
```bash
# Clone the repository (if applicable)
git clone <repository-url>
cd <project-directory>

# Create a build directory
mkdir build
cd build

# Configure the project with CMake
cmake ..

# Build the project
make
```

## How to Run
```bash
# Generate a private key
openssl genpkey -algorithm RSA -out server.key
# Generate a self-signed certificate
openssl req -new -x509 -key server.key -out server.crt -days 365 -subj "/C=CN/ST=Beijing/L=Beijing/O=Test/CN=localhost"
# Running the Server
./server
# Running the Verifier
./verifier
# Running the Client
./client
```

# Project Structure
```text
DGTOTP-TLS-main/
├─ inc/            #Header files (if not shown, assumed to exist).

├─ src/            #Contains the core source files for cryptographic and utility functions.

├─ tls/            #Contains TLS-specific client, server, and verifier implementations.

├─ CMakeLists.txt  #CMake build configuration.
```