// BeamMP, the BeamNG.drive multiplayer mod.
// Copyright (C) 2024 BeamMP Ltd., BeamMP team and contributors.
//
// BeamMP Ltd. can be contacted by electronic mail via contact@beammp.com.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

#pragma once

#include <iomanip>
#include <sstream>
#include <string>
#include <vector>
#include <cstdint>
#include <algorithm>
#include <fmt/format.h>
#include <openssl/err.h>
#include <openssl/evp.h>

// Safely encode binary data as hexadecimal string
inline std::string HexEncode(const std::vector<uint8_t>& data, size_t max_bytes = 32) {
    std::ostringstream oss;
    size_t limit = std::min(data.size(), max_bytes);
    
    for (size_t i = 0; i < limit; ++i) {
        oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(data[i]);
    }
    
    if (data.size() > max_bytes) {
        oss << "...(" << (data.size() - max_bytes) << " more bytes)";
    }
    
    return oss.str();
}

// Safely encode binary data from raw pointer as hexadecimal string
inline std::string HexEncode(const uint8_t* data, size_t size, size_t max_bytes = 32) {
    if (!data || size == 0) {
        return "(null or empty)";
    }
    std::vector<uint8_t> vec(data, data + size);
    return HexEncode(vec, max_bytes);
}

// Safely encode C-string with validation
inline std::string SafeStringEncode(const char* str, size_t max_len = 256) {
    if (!str) {
        return "(null pointer)";
    }
    
    std::string result;
    size_t len = 0;
    
    while (str[len] != '\0' && len < max_len) {
        char c = str[len];
        // Check if character is printable ASCII
        if (c >= 32 && c < 127) {
            result += c;
        } else {
            result += fmt::format("\\x{:02x}", static_cast<uint8_t>(c));
        }
        len++;
    }
    
    if (len >= max_len && str[len] != '\0') {
        result += "... (truncated)";
    }
    
    return result;
}

// Extract all OpenSSL errors from error stack
inline std::string GetOpenSSLErrors() {
    std::string errors;
    unsigned long err;
    int count = 0;
    
    while ((err = ERR_get_error()) != 0 && count < 10) {
        char buf[256];
        ERR_error_string_n(err, buf, sizeof(buf));
        
        if (!errors.empty()) {
            errors += "; ";
        }
        errors += buf;
        count++;
    }
    
    if (errors.empty()) {
        return "No error details available";
    }
    
    return errors;
}

// Structure for decryption results
struct DecryptionResult {
    bool success;
    std::vector<uint8_t> data;
    std::string error_message;
};

// Safe wrapper around EVP_PKEY_decrypt
inline DecryptionResult SafeEVPDecrypt(EVP_PKEY* pkey, const std::vector<uint8_t>& ciphertext) {
    if (!pkey) {
        return { false, {}, "EVP_PKEY is null" };
    }
    
    if (ciphertext.empty()) {
        return { false, {}, "Ciphertext is empty" };
    }
    
    if (ciphertext.size() > 10000) {  // Reasonable upper limit
        return { false, {}, fmt::format("Ciphertext too large: {} bytes", ciphertext.size()) };
    }
    
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pkey, nullptr);
    if (!ctx) {
        std::string err = GetOpenSSLErrors();
        return { false, {}, fmt::format("EVP_PKEY_CTX_new failed: {}", err) };
    }
    
    if (EVP_PKEY_decrypt_init(ctx) <= 0) {
        std::string err = GetOpenSSLErrors();
        EVP_PKEY_CTX_free(ctx);
        return { false, {}, fmt::format("EVP_PKEY_decrypt_init failed: {}", err) };
    }
    
    // Determine output size
    size_t outlen = 0;
    if (EVP_PKEY_decrypt(ctx, nullptr, &outlen, ciphertext.data(), ciphertext.size()) <= 0) {
        std::string err = GetOpenSSLErrors();
        EVP_PKEY_CTX_free(ctx);
        return { false, {}, fmt::format("Failed to determine decryption output size: {}", err) };
    }
    
    // Validate output length
    if (outlen == 0 || outlen > 100000) {
        EVP_PKEY_CTX_free(ctx);
        return { false, {}, fmt::format("Invalid output length: {} bytes", outlen) };
    }
    
    std::vector<uint8_t> plaintext(outlen);
    int ret = EVP_PKEY_decrypt(ctx, plaintext.data(), &outlen, ciphertext.data(), ciphertext.size());
    
    if (ret <= 0) {
        std::string err = GetOpenSSLErrors();
        EVP_PKEY_CTX_free(ctx);
        return { false, {}, fmt::format("Decryption failed: {} (ciphertext size: {}, first 32 bytes: {})",
                                       err, ciphertext.size(), HexEncode(ciphertext, 32)) };
    }
    
    plaintext.resize(outlen);
    EVP_PKEY_CTX_free(ctx);
    
    return { true, plaintext, "" };
}

// Safe EVP_PKEY_encrypt wrapper
inline DecryptionResult SafeEVPEncrypt(EVP_PKEY* pkey, const std::vector<uint8_t>& plaintext) {
    if (!pkey) {
        return { false, {}, "EVP_PKEY is null" };
    }
    
    if (plaintext.empty()) {
        return { false, {}, "Plaintext is empty" };
    }
    
    if (plaintext.size() > 10000) {
        return { false, {}, fmt::format("Plaintext too large: {} bytes", plaintext.size()) };
    }
    
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pkey, nullptr);
    if (!ctx) {
        std::string err = GetOpenSSLErrors();
        return { false, {}, fmt::format("EVP_PKEY_CTX_new failed: {}", err) };
    }
    
    if (EVP_PKEY_encrypt_init(ctx) <= 0) {
        std::string err = GetOpenSSLErrors();
        EVP_PKEY_CTX_free(ctx);
        return { false, {}, fmt::format("EVP_PKEY_encrypt_init failed: {}", err) };
    }
    
    // Determine output size
    size_t outlen = 0;
    if (EVP_PKEY_encrypt(ctx, nullptr, &outlen, plaintext.data(), plaintext.size()) <= 0) {
        std::string err = GetOpenSSLErrors();
        EVP_PKEY_CTX_free(ctx);
        return { false, {}, fmt::format("Failed to determine encryption output size: {}", err) };
    }
    
    if (outlen == 0 || outlen > 100000) {
        EVP_PKEY_CTX_free(ctx);
        return { false, {}, fmt::format("Invalid output length: {} bytes", outlen) };
    }
    
    std::vector<uint8_t> ciphertext(outlen);
    int ret = EVP_PKEY_encrypt(ctx, ciphertext.data(), &outlen, plaintext.data(), plaintext.size());
    
    if (ret <= 0) {
        std::string err = GetOpenSSLErrors();
        EVP_PKEY_CTX_free(ctx);
        return { false, {}, fmt::format("Encryption failed: {}", err) };
    }
    
    ciphertext.resize(outlen);
    EVP_PKEY_CTX_free(ctx);
    
    return { true, ciphertext, "" };
}
