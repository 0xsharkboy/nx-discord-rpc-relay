#include "crypto.hpp"

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#include <memory>
#include <stdexcept>

namespace relay {

namespace {

constexpr size_t kNonceLen = 12;
constexpr size_t kTagLen = 16;

constexpr char kStdAlphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
constexpr char kUrlAlphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

struct CtxDeleter {
    void operator()(EVP_CIPHER_CTX* c) const { EVP_CIPHER_CTX_free(c); }
};
using Ctx = std::unique_ptr<EVP_CIPHER_CTX, CtxDeleter>;

void random_bytes(uint8_t* out, size_t n) {
    if (RAND_bytes(out, static_cast<int>(n)) != 1) throw std::runtime_error("RAND_bytes failed");
}

std::optional<std::vector<uint8_t>> decode(std::string_view s, const char* alphabet, bool allow_padding) {
    int8_t table[256];
    for (auto& t : table) t = -1;
    for (int i = 0; i < 64; ++i) table[static_cast<uint8_t>(alphabet[i])] = static_cast<int8_t>(i);

    size_t pad = 0;
    while (allow_padding && pad < 2 && !s.empty() && s.back() == '=') {
        s.remove_suffix(1);
        ++pad;
    }
    if (s.size() % 4 == 1) return std::nullopt;
    if (pad != 0 && (s.size() + pad) % 4 != 0) return std::nullopt;

    std::vector<uint8_t> out;
    out.reserve(s.size() * 3 / 4);
    uint32_t acc = 0;
    int bits = 0;
    for (char ch : s) {
        int v = table[static_cast<uint8_t>(ch)];
        if (v < 0) return std::nullopt;
        acc = (acc << 6) | static_cast<uint32_t>(v);
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out.push_back(static_cast<uint8_t>((acc >> bits) & 0xff));
        }
    }
    return out;
}

std::string encode(std::span<const uint8_t> data, const char* alphabet) {
    std::string out;
    out.reserve((data.size() * 4 + 2) / 3);
    uint32_t acc = 0;
    int bits = 0;
    for (uint8_t b : data) {
        acc = (acc << 8) | b;
        bits += 8;
        while (bits >= 6) {
            bits -= 6;
            out.push_back(alphabet[(acc >> bits) & 0x3f]);
        }
    }
    if (bits > 0) out.push_back(alphabet[(acc << (6 - bits)) & 0x3f]);
    return out;
}

}  // namespace

std::string base64url_encode(std::span<const uint8_t> data) { return encode(data, kUrlAlphabet); }

std::optional<std::vector<uint8_t>> base64url_decode(std::string_view s) {
    return decode(s, kUrlAlphabet, false);
}

std::optional<std::vector<uint8_t>> base64_decode(std::string_view s) {
    return decode(s, kStdAlphabet, true);
}

std::string random_token(size_t bytes) {
    std::vector<uint8_t> buf(bytes);
    random_bytes(buf.data(), buf.size());
    return base64url_encode(buf);
}

std::string sha256_hex(std::string_view data) {
    uint8_t digest[EVP_MAX_MD_SIZE];
    unsigned len = 0;
    if (EVP_Digest(data.data(), data.size(), digest, &len, EVP_sha256(), nullptr) != 1)
        throw std::runtime_error("sha256 failed");
    static constexpr char hex[] = "0123456789abcdef";
    std::string out;
    out.reserve(len * 2);
    for (unsigned i = 0; i < len; ++i) {
        out.push_back(hex[digest[i] >> 4]);
        out.push_back(hex[digest[i] & 0xf]);
    }
    return out;
}

std::vector<uint8_t> seal(const std::array<uint8_t, 32>& key, std::string_view plaintext) {
    std::vector<uint8_t> out(kNonceLen + plaintext.size() + kTagLen);
    random_bytes(out.data(), kNonceLen);

    Ctx ctx(EVP_CIPHER_CTX_new());
    if (!ctx || EVP_EncryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, key.data(), out.data()) != 1)
        throw std::runtime_error("seal init failed");
    int len = 0;
    uint8_t* ct = out.data() + kNonceLen;
    if (!plaintext.empty() &&
        EVP_EncryptUpdate(ctx.get(), ct, &len, reinterpret_cast<const uint8_t*>(plaintext.data()),
                          static_cast<int>(plaintext.size())) != 1)
        throw std::runtime_error("seal failed");
    int total = len;
    if (EVP_EncryptFinal_ex(ctx.get(), ct + total, &len) != 1) throw std::runtime_error("seal failed");
    total += len;
    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_GET_TAG, kTagLen, ct + total) != 1)
        throw std::runtime_error("seal tag failed");
    return out;
}

std::optional<std::string> open(const std::array<uint8_t, 32>& key, std::span<const uint8_t> sealed) {
    if (sealed.size() < kNonceLen + kTagLen) return std::nullopt;
    const uint8_t* nonce = sealed.data();
    size_t ct_len = sealed.size() - kNonceLen - kTagLen;
    const uint8_t* ct = nonce + kNonceLen;

    Ctx ctx(EVP_CIPHER_CTX_new());
    if (!ctx || EVP_DecryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, key.data(), nonce) != 1)
        return std::nullopt;
    std::string out(ct_len, '\0');
    int len = 0;
    if (ct_len > 0 && EVP_DecryptUpdate(ctx.get(), reinterpret_cast<uint8_t*>(out.data()), &len, ct,
                                        static_cast<int>(ct_len)) != 1)
        return std::nullopt;
    uint8_t tag[kTagLen];
    std::copy(ct + ct_len, ct + ct_len + kTagLen, tag);
    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_TAG, kTagLen, tag) != 1) return std::nullopt;
    uint8_t scratch[16];
    if (EVP_DecryptFinal_ex(ctx.get(), scratch, &len) != 1) return std::nullopt;
    return out;
}

bool constant_time_equal(std::string_view a, std::string_view b) {
    if (a.size() != b.size()) return false;
    return CRYPTO_memcmp(a.data(), b.data(), a.size()) == 0;
}

}  // namespace relay
