#pragma once
#include <string>
#include <stdexcept>
#include <random>
#include <sstream>
#include <iomanip>
#include <cstring>
#include <cstdint>
#include <chrono>
#include <thread>
#include <vector>
#include <functional>
#include "types.hpp"
#include "precomp.hpp"

// ============================================================
// Entropy pipeline — defense in depth
//
// Three independent sources are XOR-mixed and SHA-256 whitened.
// The resulting 256-bit value is then rejection-sampled against
// the secp256k1 group order. As long as ANY single source is
// truly unpredictable, the output is cryptographically random.
//
//   Source 1: OS CSPRNG
//             (BCryptGenRandom / getrandom / getentropy)
//   Source 2: Hardware RNG
//             RDSEED on x86_64 (gated by CPUID), otherwise an
//             independent OS path (arc4random_buf / /dev/urandom)
//   Source 3: Runtime jitter + process state
//             high-res timers, PID/TID, stack & heap addresses,
//             repeated samples with yields — all SHA-256 folded
// ============================================================

// ---- Source 1: OS CSPRNG -----------------------------------
#ifdef _WIN32
  #ifndef NOMINMAX
  #define NOMINMAX
  #endif
  #ifndef WIN32_LEAN_AND_MEAN
  #define WIN32_LEAN_AND_MEAN
  #endif
  #include <windows.h>
  #include <bcrypt.h>
  #pragma comment(lib, "bcrypt.lib")
  static void fillRandomOS(void * buf, size_t len) {
      if (BCryptGenRandom(NULL, (PUCHAR)buf, (ULONG)len,
                          BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0)
          throw std::runtime_error("BCryptGenRandom failed");
  }
#elif defined(__linux__)
  #include <sys/random.h>
  #include <unistd.h>
  static void fillRandomOS(void * buf, size_t len) {
      size_t got = 0;
      while (got < len) {
          ssize_t r = getrandom((char *)buf + got, len - got, 0);
          if (r < 0) throw std::runtime_error("getrandom failed");
          got += (size_t)r;
      }
  }
#else  // macOS / BSD
  #include <unistd.h>
  #if defined(__APPLE__)
    #include <sys/random.h>
  #endif
  static void fillRandomOS(void * buf, size_t len) {
      size_t got = 0;
      while (got < len) {
          size_t chunk = (len - got > 256) ? 256 : (len - got);
          if (getentropy((char *)buf + got, chunk) != 0)
              throw std::runtime_error("getentropy failed");
          got += chunk;
      }
  }
#endif

// ---- Source 2 (primary on x86_64): RDSEED ------------------
// Apple removed RDSEED on their x86 platforms in some VM configs,
// so we still gate by CPUID even on __x86_64__.
#if defined(__x86_64__) || defined(_M_X64)
  #if defined(_MSC_VER)
    #include <intrin.h>
    #include <immintrin.h>
    static bool hasRdseed() {
        int regs[4] = {0, 0, 0, 0};
        __cpuidex(regs, 7, 0);
        return (regs[1] & (1 << 18)) != 0;
    }
    static bool rdseed64(uint64_t * out) {
        for (int i = 0; i < 16; ++i) {
            unsigned long long v;
            if (_rdseed64_step(&v)) { *out = (uint64_t)v; return true; }
        }
        return false;
    }
  #else
    static bool hasRdseed() {
        unsigned int eax, ebx, ecx, edx;
        __asm__ volatile("cpuid"
                         : "=a"(eax), "=b"(ebx), "=c"(ecx), "=d"(edx)
                         : "a"(7), "c"(0));
        return (ebx & (1u << 18)) != 0;
    }
    static bool rdseed64(uint64_t * out) {
        for (int i = 0; i < 16; ++i) {
            uint64_t v;
            unsigned char ok;
            __asm__ volatile(".byte 0x48, 0x0f, 0xc7, 0xf8; setc %1"
                             : "=a"(v), "=qm"(ok)
                             :
                             : "cc");
            if (ok) { *out = v; return true; }
        }
        return false;
    }
  #endif
  static bool fillRandomHW(void * buf, size_t len) {
      static const bool available = hasRdseed();
      if (!available) return false;
      uint8_t * p = (uint8_t *)buf;
      size_t got = 0;
      while (got < len) {
          uint64_t v;
          if (!rdseed64(&v)) return false;
          size_t chunk = (len - got > 8) ? 8 : (len - got);
          std::memcpy(p + got, &v, chunk);
          got += chunk;
      }
      return true;
  }
#else
  static bool fillRandomHW(void *, size_t) { return false; }
#endif

// ---- Source 2 (fallback): independent OS path --------------
#if defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__)
  #include <stdlib.h>
  static void fillRandomAlt(void * buf, size_t len) {
      arc4random_buf(buf, len);
  }
#elif defined(__linux__)
  #include <fcntl.h>
  #include <unistd.h>
  static void fillRandomAlt(void * buf, size_t len) {
      int fd = ::open("/dev/urandom", O_RDONLY);
      if (fd < 0) throw std::runtime_error("open /dev/urandom failed");
      size_t got = 0;
      while (got < len) {
          ssize_t r = ::read(fd, (char *)buf + got, len - got);
          if (r <= 0) { ::close(fd); throw std::runtime_error("/dev/urandom read failed"); }
          got += (size_t)r;
      }
      ::close(fd);
  }
#else
  static void fillRandomAlt(void * buf, size_t len) { fillRandomOS(buf, len); }
#endif

// ---- Minimal self-contained SHA-256 (FIPS 180-4) -----------
namespace sha256_detail {
    static const uint32_t K[64] = {
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    };
    static inline uint32_t rotr(uint32_t x, int n) { return (x >> n) | (x << (32 - n)); }
    static void compress(uint32_t state[8], const uint8_t block[64]) {
        uint32_t W[64];
        for (int i = 0; i < 16; ++i) {
            W[i] = ((uint32_t)block[i*4]   << 24) |
                   ((uint32_t)block[i*4+1] << 16) |
                   ((uint32_t)block[i*4+2] <<  8) |
                   ((uint32_t)block[i*4+3]);
        }
        for (int i = 16; i < 64; ++i) {
            uint32_t s0 = rotr(W[i-15], 7) ^ rotr(W[i-15], 18) ^ (W[i-15] >> 3);
            uint32_t s1 = rotr(W[i-2], 17) ^ rotr(W[i-2], 19) ^ (W[i-2] >> 10);
            W[i] = W[i-16] + s0 + W[i-7] + s1;
        }
        uint32_t a=state[0], b=state[1], c=state[2], d=state[3];
        uint32_t e=state[4], f=state[5], g=state[6], h=state[7];
        for (int i = 0; i < 64; ++i) {
            uint32_t S1 = rotr(e,6) ^ rotr(e,11) ^ rotr(e,25);
            uint32_t ch = (e & f) ^ ((~e) & g);
            uint32_t t1 = h + S1 + ch + K[i] + W[i];
            uint32_t S0 = rotr(a,2) ^ rotr(a,13) ^ rotr(a,22);
            uint32_t mj = (a & b) ^ (a & c) ^ (b & c);
            uint32_t t2 = S0 + mj;
            h=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
        }
        state[0]+=a; state[1]+=b; state[2]+=c; state[3]+=d;
        state[4]+=e; state[5]+=f; state[6]+=g; state[7]+=h;
    }
}

static void sha256(uint8_t out[32], const uint8_t * data, size_t len) {
    uint32_t state[8] = {
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    };
    uint64_t bits = (uint64_t)len * 8ULL;
    size_t i = 0;
    for (; i + 64 <= len; i += 64) sha256_detail::compress(state, data + i);

    uint8_t tail[128] = {0};
    size_t rem = len - i;
    if (rem) std::memcpy(tail, data + i, rem);
    tail[rem] = 0x80;
    size_t padded = (rem < 56) ? 64 : 128;
    for (int j = 0; j < 8; ++j)
        tail[padded - 1 - j] = (uint8_t)(bits >> (j * 8));
    sha256_detail::compress(state, tail);
    if (padded == 128) sha256_detail::compress(state, tail + 64);

    for (int k = 0; k < 8; ++k) {
        out[k*4]   = (uint8_t)(state[k] >> 24);
        out[k*4+1] = (uint8_t)(state[k] >> 16);
        out[k*4+2] = (uint8_t)(state[k] >>  8);
        out[k*4+3] = (uint8_t)(state[k]);
    }
}

// ---- Source 3: timing + process state ----------------------
static void fillRandomTiming(uint8_t out[32]) {
    std::vector<uint8_t> pool;
    pool.reserve(512);
    auto push = [&](const void * p, size_t n) {
        const uint8_t * b = (const uint8_t *)p;
        pool.insert(pool.end(), b, b + n);
    };

    auto hr = std::chrono::high_resolution_clock::now().time_since_epoch().count();
    push(&hr, sizeof(hr));
    auto sc = std::chrono::steady_clock::now().time_since_epoch().count();
    push(&sc, sizeof(sc));
    auto sy = std::chrono::system_clock::now().time_since_epoch().count();
    push(&sy, sizeof(sy));

    int local_var = 0;
    void * stack_addr = &local_var;
    push(&stack_addr, sizeof(stack_addr));

    uint8_t * heap_ptr = new uint8_t(0);
    void * heap_addr = (void *)heap_ptr;
    push(&heap_addr, sizeof(heap_addr));
    delete heap_ptr;

    size_t tid = std::hash<std::thread::id>{}(std::this_thread::get_id());
    push(&tid, sizeof(tid));

#ifdef _WIN32
    DWORD pid = GetCurrentProcessId();
#else
    pid_t pid = getpid();
#endif
    push(&pid, sizeof(pid));

    // Repeated high-resolution samples with yields for scheduler jitter.
    for (int j = 0; j < 64; ++j) {
        auto t = std::chrono::high_resolution_clock::now().time_since_epoch().count();
        push(&t, sizeof(t));
        std::this_thread::yield();
    }

    sha256(out, pool.data(), pool.size());
}

// ============================================================
// secp256k1 constants
// ============================================================
static const mp_word SECP256K1_N[MP_NWORDS] = {
    0xD0364141, 0xBFD25E8C, 0xAF48A03B, 0xBAAEDCE6,
    0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF
};
static const mp_word SECP256K1_P[MP_NWORDS] = {
    0xFFFFFC2F, 0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFF,
    0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF
};

class KeyGen {
public:
    // Generate a cryptographically random 256-bit private key.
    // Defense in depth: XOR three independent sources, SHA-256
    // whiten, then rejection-sample against the curve order.
    static void generatePrivateKey(mp_number & privKey) {
        do {
            uint8_t buf1[32], buf2[32], buf3[32], out[32];

            fillRandomOS(buf1, 32);                               // Source 1
            if (!fillRandomHW(buf2, 32)) fillRandomAlt(buf2, 32); // Source 2
            fillRandomTiming(buf3);                               // Source 3

            for (int i = 0; i < 32; ++i) out[i] = buf1[i] ^ buf2[i] ^ buf3[i];
            sha256(out, out, 32);

            std::memcpy(privKey.d, out, 32);
        } while (!isLessThan(privKey.d, SECP256K1_N) || isZero(privKey));
    }

    // Compute public key = privKey * G using precomputed table
    // g_precomp is organized as 4 groups of 2040 points:
    //   group k (k=0..3): contains i*2^(64k) * G for i=1..255, each stored as 8 consecutive points
    //   Layout: g_precomp[k * 2040 + (i-1) * 8 + j] where j indexes sub-multiples
    // Actually the layout is: 4 groups of 255 entries, each entry is 8 points
    // Standard double-and-add scalar multiplication: privKey * G
    // Uses g_precomp[0] as the generator point G
    static void computePublicKey(const mp_number & privKey, point & pubKey) {
        point G = g_precomp[0]; // Generator point
        point result;
        point base = G;
        bool isFirst = true;

        for (int word = 0; word < MP_NWORDS; ++word) {
            mp_word w = privKey.d[word];
            for (int bit = 0; bit < 32; ++bit) {
                if (w & (1u << bit)) {
                    if (isFirst) {
                        result = base;
                        isFirst = false;
                    } else {
                        pointAdd(result, base);
                    }
                }
                point baseCopy = base;
                pointDouble(baseCopy, base);
            }
        }

        pubKey = result;
    }

    // Convert mp_number to hex string (big-endian)
    static std::string toHex(const mp_number & n) {
        std::ostringstream ss;
        ss << std::hex << std::setfill('0');
        for (int i = MP_NWORDS - 1; i >= 0; --i) {
            ss << std::setw(8) << n.d[i];
        }
        return ss.str();
    }

    // Convert point to 128-char hex public key string
    static std::string publicKeyToHex(const point & p) {
        return toHex(p.x) + toHex(p.y);
    }

    // Add two 256-bit numbers mod n (curve order), result in out
    static void addModN(mp_number & out, const mp_number & a, const mp_number & b) {
        mp_word carry = 0;
        mp_word sum[MP_NWORDS];
        for (int i = 0; i < MP_NWORDS; ++i) {
            cl_ulong s = (cl_ulong)a.d[i] + b.d[i] + carry;
            sum[i] = (mp_word)(s & 0xFFFFFFFF);
            carry = (mp_word)(s >> 32);
        }
        // If sum >= n, subtract n
        if (carry || !isLessThan(sum, SECP256K1_N)) {
            mp_word borrow = 0;
            for (int i = 0; i < MP_NWORDS; ++i) {
                cl_ulong diff = (cl_ulong)sum[i] - SECP256K1_N[i] - borrow;
                out.d[i] = (mp_word)(diff & 0xFFFFFFFF);
                borrow = (diff >> 63) & 1;
            }
        } else {
            for (int i = 0; i < MP_NWORDS; ++i) out.d[i] = sum[i];
        }
    }

    // Parse hex string to mp_number (big-endian hex)
    static mp_number fromHex(const std::string & hex) {
        mp_number r;
        memset(&r, 0, sizeof(r));
        for (int i = 0; i < MP_NWORDS; ++i) {
            int strIdx = (MP_NWORDS - 1 - i) * 8;
            if (strIdx + 8 <= (int)hex.length()) {
                r.d[i] = (mp_word)strtoul(hex.substr(strIdx, 8).c_str(), nullptr, 16);
            }
        }
        return r;
    }

private:
    static bool isZero(const mp_number & n) {
        for (int i = 0; i < MP_NWORDS; ++i) {
            if (n.d[i] != 0) return false;
        }
        return true;
    }

    static bool isLessThan(const mp_word * a, const mp_word * b) {
        for (int i = MP_NWORDS - 1; i >= 0; --i) {
            if (a[i] < b[i]) return true;
            if (a[i] > b[i]) return false;
        }
        return false; // equal
    }

    // Field operations mod p
    static void fieldAdd(mp_word * r, const mp_word * a, const mp_word * b) {
        mp_word carry = 0;
        for (int i = 0; i < MP_NWORDS; ++i) {
            cl_ulong s = (cl_ulong)a[i] + b[i] + carry;
            r[i] = (mp_word)(s & 0xFFFFFFFF);
            carry = (mp_word)(s >> 32);
        }
        if (carry || !isLessThan(r, SECP256K1_P)) {
            mp_word borrow = 0;
            for (int i = 0; i < MP_NWORDS; ++i) {
                cl_ulong diff = (cl_ulong)r[i] - SECP256K1_P[i] - borrow;
                r[i] = (mp_word)(diff & 0xFFFFFFFF);
                borrow = (diff >> 63) & 1;
            }
        }
    }

    static void fieldSub(mp_word * r, const mp_word * a, const mp_word * b) {
        mp_word borrow = 0;
        for (int i = 0; i < MP_NWORDS; ++i) {
            cl_ulong diff = (cl_ulong)a[i] - b[i] - borrow;
            r[i] = (mp_word)(diff & 0xFFFFFFFF);
            borrow = (diff >> 63) & 1;
        }
        if (borrow) {
            mp_word carry = 0;
            for (int i = 0; i < MP_NWORDS; ++i) {
                cl_ulong s = (cl_ulong)r[i] + SECP256K1_P[i] + carry;
                r[i] = (mp_word)(s & 0xFFFFFFFF);
                carry = (mp_word)(s >> 32);
            }
        }
    }

    static void fieldMul(mp_word * r, const mp_word * a, const mp_word * b) {
        // Schoolbook 256x256 -> 512-bit multiply
        cl_ulong product[MP_NWORDS * 2] = {};
        for (int i = 0; i < MP_NWORDS; ++i) {
            cl_ulong carry = 0;
            for (int j = 0; j < MP_NWORDS; ++j) {
                cl_ulong v = (cl_ulong)a[i] * b[j] + product[i + j] + carry;
                product[i + j] = v & 0xFFFFFFFF;
                carry = v >> 32;
            }
            product[i + MP_NWORDS] += carry;
        }

        // Reduce mod p where p = 2^256 - C, C = 0x1000003D1
        // hi * 2^256 ≡ hi * C (mod p)
        // Repeat until fits in 256 bits + small overflow
        for (int pass = 0; pass < 3; ++pass) {
            cl_ulong carry = 0;
            for (int i = 0; i < MP_NWORDS; ++i) {
                cl_ulong hi = product[MP_NWORDS + i];
                product[MP_NWORDS + i] = 0;
                // hi * C = hi * 0x1000003D1 = hi<<32 + hi*0x3D1
                cl_ulong lo_part = hi * 0x3D1ULL + carry + product[i];
                product[i] = lo_part & 0xFFFFFFFF;
                carry = (lo_part >> 32) + hi; // hi<<32 contribution goes to next word
            }
            // Remaining carry: carry * 2^256 ≡ carry * C (mod p)
            // where C = 0x1000003D1 = 2^32 + 0x3D1
            if (carry) {
                cl_ulong lo_part = carry * 0x3D1ULL + product[0];
                product[0] = lo_part & 0xFFFFFFFF;
                cl_ulong hi_part = (lo_part >> 32) + carry; // carry * 2^32 term
                product[1] += hi_part;
                for (int i = 1; i < MP_NWORDS && product[i] > 0xFFFFFFFF; ++i) {
                    product[i + 1] += product[i] >> 32;
                    product[i] &= 0xFFFFFFFF;
                }
            }
        }

        for (int i = 0; i < MP_NWORDS; ++i) r[i] = (mp_word)product[i];
        // Final reduction: if r >= p, subtract p
        if (!isLessThan(r, SECP256K1_P)) {
            mp_word borrow = 0;
            for (int i = 0; i < MP_NWORDS; ++i) {
                cl_ulong diff = (cl_ulong)r[i] - SECP256K1_P[i] - borrow;
                r[i] = (mp_word)(diff & 0xFFFFFFFF);
                borrow = (diff >> 63) & 1;
            }
        }
    }

    static void fieldInv(mp_word * r, const mp_word * a) {
        // Fermat's little theorem: a^(-1) = a^(p-2) mod p
        mp_word base[MP_NWORDS], result_inv[MP_NWORDS];
        memcpy(base, a, sizeof(mp_word) * MP_NWORDS);

        // p-2 in words
        mp_word exp[MP_NWORDS];
        memcpy(exp, SECP256K1_P, sizeof(mp_word) * MP_NWORDS);
        // Subtract 2 from exp
        if (exp[0] >= 2) { exp[0] -= 2; }
        else { exp[0] -= 2; /* wraps */ for (int i = 1; i < MP_NWORDS; ++i) { if (exp[i]-- != 0) break; } }

        // Set result = 1
        memset(result_inv, 0, sizeof(result_inv));
        result_inv[0] = 1;

        // Square and multiply
        for (int bit = 255; bit >= 0; --bit) {
            fieldMul(result_inv, result_inv, result_inv); // square
            int wordIdx = bit / 32;
            int bitIdx = bit % 32;
            if (exp[wordIdx] & (1u << bitIdx)) {
                fieldMul(result_inv, result_inv, base); // multiply
            }
        }

        memcpy(r, result_inv, sizeof(mp_word) * MP_NWORDS);
    }

    // EC point doubling: out = 2 * in (affine coordinates, secp256k1: a=0)
    static void pointDouble(const point & in, point & out) {
        // lambda = 3 * x^2 / (2 * y)  (a=0 for secp256k1)
        mp_word x2[MP_NWORDS], num[MP_NWORDS], den[MP_NWORDS], lambda[MP_NWORDS];
        mp_word lambda2[MP_NWORDS], newx[MP_NWORDS], newy[MP_NWORDS], tmp[MP_NWORDS];

        fieldMul(x2, in.x.d, in.x.d); // x^2
        // 3*x^2 = x^2 + x^2 + x^2
        fieldAdd(num, x2, x2);
        fieldAdd(num, num, x2);
        // 2*y
        fieldAdd(den, in.y.d, in.y.d);
        fieldInv(den, den);
        fieldMul(lambda, num, den);

        // newx = lambda^2 - 2*x
        fieldMul(lambda2, lambda, lambda);
        fieldSub(newx, lambda2, in.x.d);
        fieldSub(newx, newx, in.x.d);

        // newy = lambda * (x - newx) - y
        fieldSub(tmp, in.x.d, newx);
        fieldMul(newy, lambda, tmp);
        fieldSub(newy, newy, in.y.d);

        memcpy(out.x.d, newx, sizeof(mp_word) * MP_NWORDS);
        memcpy(out.y.d, newy, sizeof(mp_word) * MP_NWORDS);
    }

    // EC point addition: result += p (affine coordinates)
    static void pointAdd(point & result, const point & p) {
        // lambda = (p.y - result.y) / (p.x - result.x)
        mp_word dx[MP_NWORDS], dy[MP_NWORDS], lambda[MP_NWORDS];
        mp_word lambda2[MP_NWORDS], newx[MP_NWORDS], newy[MP_NWORDS];

        fieldSub(dx, p.x.d, result.x.d);
        fieldSub(dy, p.y.d, result.y.d);
        fieldInv(dx, dx);
        fieldMul(lambda, dy, dx);

        // newx = lambda^2 - result.x - p.x
        fieldMul(lambda2, lambda, lambda);
        fieldSub(newx, lambda2, result.x.d);
        fieldSub(newx, newx, p.x.d);

        // newy = lambda * (result.x - newx) - result.y
        mp_word tmp[MP_NWORDS];
        fieldSub(tmp, result.x.d, newx);
        fieldMul(newy, lambda, tmp);
        fieldSub(newy, newy, result.y.d);

        memcpy(result.x.d, newx, sizeof(mp_word) * MP_NWORDS);
        memcpy(result.y.d, newy, sizeof(mp_word) * MP_NWORDS);
    }
};
