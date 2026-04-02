# profanity2

GPU-accelerated Ethereum vanity address generator. Single binary, zero dependencies.

Fork of [1inch/profanity2](https://github.com/1inch/profanity2) with built-in key generation — no more manual openssl + private key math.

## Quick Start

```bash
# Find address starting with "dead"
./profanity2 --prefix dead

# Find address ending with "beef"
./profanity2 --suffix beef

# Both prefix and suffix
./profanity2 --prefix dead --suffix beef

# Benchmark GPU speed
./profanity2 --benchmark
```

The output private key is **ready to import** into any wallet. No additional computation needed.

## Download

Pre-built binaries for macOS (ARM/x64), Linux, and Windows are available on the [Releases](../../releases) page.

## Build from Source

**macOS:**
```bash
make
```

**Linux:**
```bash
sudo apt-get install ocl-icd-opencl-dev
make
```

**Windows (MSVC):**
```
vcpkg install opencl:x64-windows
cl /std:c++14 /O2 /EHsc /I<opencl_include> Dispatcher.cpp Mode.cpp precomp.cpp profanity.cpp SpeedSample.cpp /Fe:profanity2.exe /link /LIBPATH:<opencl_lib> OpenCL.lib
```

## How It Works

1. Generates a random secp256k1 keypair internally
2. Passes the public key to the GPU search engine
3. GPU finds a vanity address matching your pattern at ~100 MH/s
4. Automatically computes the final private key (seed + partial key mod n)
5. Outputs the ready-to-use private key

**Safe by design:** the GPU only sees the public key, never the private key.

## Advanced Usage

All original profanity2 flags still work:

```bash
# Manual public key mode (original flow)
./profanity2 -z <128-hex-pubkey> --matching deadXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXbeef

# Score modes
./profanity2 --zeros          # Most zeros
./profanity2 --letters        # Most letters
./profanity2 --mirror         # Mirror pattern

# Contract address
./profanity2 --prefix dead --contract

# Performance tuning
./profanity2 --prefix dead -I 256    # Faster init, lower throughput
./profanity2 --prefix dead -n        # Skip OpenCL cache
```

## Performance

| GPU | Speed |
|-----|-------|
| Apple M4 | ~100 MH/s |
| RTX 4090 | ~1000+ MH/s |
| RTX 3060 | ~300 MH/s |

Estimated time for pattern matching:

| Pattern Length | Expected Time @ 100 MH/s |
|---------------|--------------------------|
| 4 hex chars | < 1s |
| 6 hex chars | ~2s |
| 8 hex chars | ~40s |
| 10 hex chars | ~3h |

## Security

- Based on profanity2's "safe by design" architecture
- Private key never exposed to GPU
- Uses `std::random_device` for cryptographic randomness
- OpenCL kernels embedded in binary (no external `.cl` files needed)

## Credits

- Original [profanity](https://github.com/johguse/profanity) by Johan Gustafsson
- [profanity2](https://github.com/1inch/profanity2) security fix by 1inch
