// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

#include <array>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace relay {

std::string random_token(size_t bytes);
std::string sha256_hex(std::string_view data);
std::string base64url_encode(std::span<const uint8_t> data);
std::optional<std::vector<uint8_t>> base64url_decode(std::string_view s);
std::optional<std::vector<uint8_t>> base64_decode(std::string_view s);

// Output layout: 12-byte nonce | ciphertext | 16-byte tag.
std::vector<uint8_t> seal(const std::array<uint8_t, 32>& key, std::string_view plaintext);
std::optional<std::string> open(const std::array<uint8_t, 32>& key, std::span<const uint8_t> sealed);

bool constant_time_equal(std::string_view a, std::string_view b);

}  // namespace relay
