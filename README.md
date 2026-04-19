# profanity2

[中文文档](README_zh.md)

GPU-accelerated Ethereum vanity address generator. Single binary, zero dependencies.

Fork of [1inch/profanity2](https://github.com/1inch/profanity2) — added built-in key generation, `--prefix`/`--suffix` shortcuts, and embedded OpenCL kernels so the entire tool is one file.

## Usage

```bash
./profanity2 --prefix dead
./profanity2 --suffix beef
./profanity2 --prefix dead --suffix beef
./profanity2 --prefix dead --contract    # contract address
./profanity2 --benchmark                 # test GPU speed
```

Output includes the final private key, ready to import into any wallet.

## Download

Pre-built binaries: [Releases](../../releases)

- `profanity2-macos-arm64` — macOS (Apple Silicon)
- `profanity2-linux-x64`
- `profanity2-windows-x64`

## Build

```bash
# macOS
make

# Linux
sudo apt-get install -y ocl-icd-opencl-dev && make

# Windows (MSVC + vcpkg)
vcpkg install opencl:x64-windows
cl /std:c++14 /O2 /EHsc /I<opencl_include> Dispatcher.cpp Mode.cpp precomp.cpp profanity.cpp SpeedSample.cpp /Fe:profanity2.exe /link /LIBPATH:<opencl_lib> OpenCL.lib
```

## What Changed from Upstream

| Feature | upstream 1inch/profanity2 | this fork |
|---------|--------------------------|-----------|
| Key generation | manual openssl + math | built-in, automatic |
| Private key output | partial key (need manual addition) | final key, ready to use |
| Quick pattern | `--matching deadXXXX...` (pad 40 chars) | `--prefix dead --suffix beef` |
| .cl kernel files | required at runtime | embedded in binary |
| Deployment | binary + 2 .cl files | single binary |

## How It Works

1. Generates a random secp256k1 keypair internally
2. Passes the public key to the GPU search engine
3. GPU finds a vanity address matching your pattern
4. Computes the final private key: `seed_key + partial_key mod n`
5. Outputs the ready-to-use private key and address

**Safe by design** — the GPU only sees the public key, never the private key.

**Hardened RNG** (v1.1.0+) — the seed private key is produced by XOR-mixing three independent entropy sources (OS CSPRNG + hardware RDSEED / `arc4random_buf` + runtime timing jitter) and SHA-256 whitening the result. The output stays cryptographically random even if any single source is compromised — including the AMD Zen 5 RDSEED bias (CVE-2025-62626), which is mitigated by using the 64-bit variant and never relying on RDSEED alone.

## Performance

| GPU | Speed |
|-----|-------|
| Apple M4 | ~100 MH/s |
| RTX 4090 | ~1000+ MH/s |
| RTX 3060 | ~300 MH/s |

| Pattern | Est. time @ 100 MH/s |
|---------|----------------------|
| 4 chars | < 1s |
| 6 chars | ~2s |
| 8 chars | ~40s |
| 10 chars | ~3h |

## Advanced

All upstream flags still work:

```bash
# Original manual mode
./profanity2 -z <128-hex-pubkey> --matching deadXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXbeef

# Score modes
./profanity2 --zeros
./profanity2 --letters
./profanity2 --mirror

# Tuning
./profanity2 --prefix dead -I 256    # faster init, lower throughput
./profanity2 --prefix dead -n        # skip OpenCL cache
```

## Credits

- [profanity](https://github.com/johguse/profanity) by Johan Gustafsson
- [profanity2](https://github.com/1inch/profanity2) by 1inch Network
