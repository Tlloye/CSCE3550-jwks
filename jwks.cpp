#include "httplib.h"
#include "json.hpp"
#include <iostream>
#include <ctime>
#include <string>
#include <vector>
#include <stdexcept>
#include <cstdio>
#include <cctype>
#include <csignal>
#include <cstdlib>


using json = nlohmann::json;

struct KeyEntry {
    std::string kid;
    std::string priv_pem_path; // path to private key for signing (OpenSSL CLI)
    json jwk;                  // public JWK fields
    std::time_t expires_at;    // epoch seconds
};

static bool is_expired(std::time_t now, const KeyEntry& k) {
    return k.expires_at <= now;
}

// ---------- base64url ----------
static std::string base64url_encode_bytes(const unsigned char* data, size_t len) {
    static const char* b64 =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out;
    out.reserve(((len + 2) / 3) * 4);

    int val = 0;
    int valb = -6;
    for (size_t i = 0; i < len; i++) {
        val = (val << 8) + data[i];
        valb += 8;
        while (valb >= 0) {
            out.push_back(b64[(val >> valb) & 0x3F]);
            valb -= 6;
        }
    }
    if (valb > -6) out.push_back(b64[((val << 8) >> (valb + 8)) & 0x3F]);

    // padding not used in base64url
    for (char& ch : out) {
        if (ch == '+') ch = '-';
        else if (ch == '/') ch = '_';
    }
    return out;
}

static std::string base64url_encode_string(const std::string& s) {
    return base64url_encode_bytes(reinterpret_cast<const unsigned char*>(s.data()), s.size());
}

// ---------- small helpers ----------
static std::string trim(const std::string& s) {
    size_t a = 0;
    while (a < s.size() && std::isspace(static_cast<unsigned char>(s[a]))) a++;
    size_t b = s.size();
    while (b > a && std::isspace(static_cast<unsigned char>(s[b - 1]))) b--;
    return s.substr(a, b - a);
}

static std::string run_cmd_text(const std::string& cmd) {
    FILE* pipe = popen(cmd.c_str(), "r");
    if (!pipe) throw std::runtime_error("popen failed for: " + cmd);

    std::string out;
    char buf[4096];
    while (fgets(buf, sizeof(buf), pipe)) out += buf;

    int rc = pclose(pipe);
    (void)rc;
    return out;
}

static std::vector<unsigned char> run_cmd_binary(const std::string& cmd) {
    FILE* pipe = popen(cmd.c_str(), "r");
    if (!pipe) throw std::runtime_error("popen failed for: " + cmd);

    std::vector<unsigned char> out;
    unsigned char buf[4096];
    while (true) {
        size_t n = fread(buf, 1, sizeof(buf), pipe);
        if (n > 0) out.insert(out.end(), buf, buf + n);
        if (n < sizeof(buf)) break;
    }

    int rc = pclose(pipe);
    (void)rc;
    return out;
}

static std::vector<unsigned char> hex_to_bytes(std::string hex) {
    hex = trim(hex);
    if (hex.rfind("Modulus=", 0) == 0) hex = hex.substr(std::string("Modulus=").size());
    if (hex.rfind("modulus=", 0) == 0) hex = hex.substr(std::string("modulus=").size());
    hex = trim(hex);

    // allow possible "00" prefix or newlines
    std::vector<unsigned char> bytes;
    bytes.reserve(hex.size() / 2);

    auto hexval = [](char c) -> int {
        if ('0' <= c && c <= '9') return c - '0';
        if ('a' <= c && c <= 'f') return 10 + (c - 'a');
        if ('A' <= c && c <= 'F') return 10 + (c - 'A');
        return -1;
    };

    int hi = -1;
    for (char c : hex) {
        int v = hexval(c);
        if (v < 0) continue; // skip non-hex
        if (hi < 0) hi = v;
        else {
            bytes.push_back(static_cast<unsigned char>((hi << 4) | v));
            hi = -1;
        }
    }
    return bytes;
}

// Extract RSA modulus using openssl CLI: openssl rsa -in KEY -noout -modulus
static std::string jwk_n_from_private_key(const std::string& priv_path) {
    std::string cmd = "openssl rsa -in " + priv_path + " -noout -modulus 2>/dev/null";
    std::string out = run_cmd_text(cmd);
    // output: Modulus=ABCDEF...
    auto pos = out.find('=');
    if (pos == std::string::npos) throw std::runtime_error("Could not parse modulus from openssl output");
    std::string hex = out.substr(pos + 1);

    auto bytes = hex_to_bytes(hex);
    if (bytes.empty()) throw std::runtime_error("Modulus bytes empty");

    return base64url_encode_bytes(bytes.data(), bytes.size());
}

// Sign signing_input file with openssl dgst -sha256 -sign KEY -binary FILE
static std::string rs256_sign_b64url_cli(const std::string& priv_path, const std::string& signing_input) {
    // write signing_input to temp file
    const std::string tmp = "signing_input.tmp";
    {
        FILE* f = fopen(tmp.c_str(), "wb");
        if (!f) throw std::runtime_error("Failed to create temp file");
        fwrite(signing_input.data(), 1, signing_input.size(), f);
        fclose(f);
    }

    std::string cmd = "openssl dgst -sha256 -sign " + priv_path + " -binary " + tmp + " 2>/dev/null";
    auto sig = run_cmd_binary(cmd);

    // remove temp file
    std::remove(tmp.c_str());

    if (sig.empty()) throw std::runtime_error("Signature output empty");
    return base64url_encode_bytes(sig.data(), sig.size());
}

static void handle_signal(int) {
    std::exit(0);  // ensures gcov writes coverage data
}



int main() {
    httplib::Server svr;
    std::signal(SIGTERM, handle_signal);
    std::signal(SIGINT, handle_signal);



    std::time_t now = std::time(nullptr);

    // IMPORTANT: these files must exist in the same folder
    // Generate them with:
    //   openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out valid_private.pem
    //   openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out expired_private.pem
    KeyEntry validKey;
    validKey.kid = "valid-kid";
    validKey.priv_pem_path = "valid_private.pem";
    validKey.expires_at = now + 3600;

    KeyEntry expiredKey;
    expiredKey.kid = "expired-kid";
    expiredKey.priv_pem_path = "expired_private.pem";
    expiredKey.expires_at = now - 3600;

    // Build real JWKs (n from modulus, e is typically 65537 => "AQAB")
    // If your generated key uses a different exponent (rare), we can extract it too.
    validKey.jwk = {
        {"kty", "RSA"},
        {"kid", validKey.kid},
        {"use", "sig"},
        {"alg", "RS256"},
        {"n", jwk_n_from_private_key(validKey.priv_pem_path)},
        {"e", "AQAB"}
    };

    expiredKey.jwk = {
        {"kty", "RSA"},
        {"kid", expiredKey.kid},
        {"use", "sig"},
        {"alg", "RS256"},
        {"n", jwk_n_from_private_key(expiredKey.priv_pem_path)},
        {"e", "AQAB"}
    };

    std::vector<KeyEntry> keys{ validKey, expiredKey };

    svr.Get("/", [](const httplib::Request& req, httplib::Response& res) {
        (void)req;
        res.status = 200;
        res.set_content("JWKS Server Running", "text/plain");
    });

    svr.Get("/.well-known/jwks.json", [&keys](const httplib::Request& req, httplib::Response& res) {
        (void)req;
        std::time_t now = std::time(nullptr);

        json out;
        out["keys"] = json::array();
        for (const auto& k : keys) {
            if (!is_expired(now, k)) out["keys"].push_back(k.jwk);
        }

        res.status = 200;
        res.set_content(out.dump(), "application/json");
    });

    svr.Post("/auth", [&keys](const httplib::Request& req, httplib::Response& res) {
        bool wantExpired = req.has_param("expired") && req.get_param_value("expired") == "true";
        std::string chosenKid = wantExpired ? "expired-kid" : "valid-kid";

        const KeyEntry* chosen = nullptr;
        for (const auto& k : keys) {
            if (k.kid == chosenKid) { chosen = &k; break; }
        }
        if (!chosen) {
            res.status = 500;
            res.set_content("Key not found", "text/plain");
            return;
        }

        std::time_t now = std::time(nullptr);
        std::time_t exp = wantExpired ? (now - 300) : (now + 300);

        json header = {
            {"alg", "RS256"},
            {"typ", "JWT"},
            {"kid", chosenKid}
        };

        json payload = {
            {"sub", "student"},
            {"iat", now},
            {"exp", exp}
        };

        std::string encodedHeader = base64url_encode_string(header.dump());
        std::string encodedPayload = base64url_encode_string(payload.dump());
        std::string signing_input = encodedHeader + "." + encodedPayload;

        std::string sig;
        try {
            sig = rs256_sign_b64url_cli(chosen->priv_pem_path, signing_input);
        } catch (const std::exception& e) {
            res.status = 500;
            res.set_content(std::string("Signing failed: ") + e.what(), "text/plain");
            return;
        }

        std::string token = signing_input + "." + sig;

        json response = {
            {"token", token},
            {"kid", chosenKid},
            {"exp", exp}
        };

        res.status = 200;
        res.set_content(response.dump(), "application/json");
    });

    svr.Get("/auth", [](const httplib::Request& req, httplib::Response& res) {
        (void)req;
        res.status = 405;
        res.set_content("Method Not Allowed", "text/plain");
    });

    std::cout << "Server running on port 8080...\n";
    svr.listen("0.0.0.0", 8080);
}
