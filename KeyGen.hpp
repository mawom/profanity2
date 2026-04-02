#pragma once
#include <string>
#include <stdexcept>
#include <random>
#include <sstream>
#include <iomanip>
#include <cstring>
#include "types.hpp"
#include "precomp.hpp"

// secp256k1 field prime p = 2^256 - 2^32 - 977
// secp256k1 curve order n
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
    // Generate a cryptographically random 256-bit private key
    static void generatePrivateKey(mp_number & privKey) {
        std::random_device rd;
        for (int i = 0; i < MP_NWORDS; ++i) {
            privKey.d[i] = rd();
        }
        // Ensure key < n (curve order) by clearing top bit if needed
        // Simple rejection sampling
        while (!isLessThan(privKey.d, SECP256K1_N) || isZero(privKey)) {
            for (int i = 0; i < MP_NWORDS; ++i) {
                privKey.d[i] = rd();
            }
        }
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
            // carry goes into overflow
            if (carry) {
                cl_ulong lo_part = carry * 0x3D1ULL + product[0];
                product[0] = lo_part & 0xFFFFFFFF;
                carry = (lo_part >> 32) + carry; // Hmm this recurse
                // Actually for small carry, just add to product[1]
                product[1] += carry;
                // Handle propagation
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
