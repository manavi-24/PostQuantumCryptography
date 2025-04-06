#include <iostream>
#include <random>
#include <bitset>
#include <cmath>
#include <vector>
#include <string>
#include <stdexcept>
#include <memory>
#include <unordered_map>
#include <chrono>
#include <array>
#include <iomanip> // For hex output

class SecureRandom {
public:
    // Returns a cryptographically secure random 64-bit unsigned integer
    static uint64_t random_u64() {
        static std::random_device rd;
        uint64_t r = ((uint64_t)rd() << 32) | rd();
        return r;
    }

    // Returns a cryptographically secure random integer in the range [min, max]
    static int uniform_int(int min, int max) {
        static std::random_device rd;
        std::uniform_int_distribution<int> dist(min, max);
        return dist(rd);
    }

    // Returns a cryptographically secure sample from a discrete Gaussian distribution
    static int discrete_gaussian_sample(double sigma) {
        static std::random_device rd;
        // In production, use a more secure method and constant-time implementation
        std::mt19937_64 engine(rd());
        std::normal_distribution<double> dist(0.0, sigma);
        return static_cast<int>(round(dist(engine)));
    }

    // Generate a secure random string of specified length
    static std::string random_string(size_t length) {
        const std::string chars = 
            "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
        std::string result;
        result.reserve(length);
        
        for (size_t i = 0; i < length; ++i) {
            result += chars[uniform_int(0, chars.length() - 1)];
        }
        
        return result;
    }

    // Generate random bytes for symmetric key
    static std::vector<uint8_t> random_bytes(size_t count) {
        std::vector<uint8_t> bytes(count);
        static std::random_device rd;
        std::uniform_int_distribution<int> dist(0, 255);
        
        for (size_t i = 0; i < count; ++i) {
            bytes[i] = static_cast<uint8_t>(dist(rd));
        }
        
        return bytes;
    }
};

// --- Modular Arithmetic Utilities ---
class ModularArithmetic {
public:
    static int mod(int x, int modulus) {
        return ((x % modulus) + modulus) % modulus;
    }
    
    static int modexp(int base, int exp, int mod) {
        int result = 1;
        base = mod ? (base % mod) : base;
        while (exp > 0) {
            if (exp & 1)
                result = (int)((1LL * result * base) % mod);
            base = (int)((1LL * base * base) % mod);
            exp >>= 1;
        }
        return result;
    }

    static int modinv(int x, int mod) {
        return modexp(x, mod - 2, mod);
    }
};

// --- AES Symmetric Encryption (simplified) ---
class AES {
private:
    static constexpr size_t KEY_SIZE = 128;  // 1024-bit key
    static constexpr size_t BLOCK_SIZE = 16; // 128-bit blocks
    std::vector<uint8_t> key;
    
    // In a real implementation, this would use a crypto library like OpenSSL
    // This is a simplified placeholder - NOT secure for production use!
    std::vector<uint8_t> simpleXorEncrypt(const std::vector<uint8_t>& data, const std::vector<uint8_t>& iv) const {
        std::vector<uint8_t> result = data;
        std::vector<uint8_t> expanded_key = key;
        
        // Expand key with IV for basic CBC-like mode
        for (size_t i = 0; i < iv.size(); i++) {
            expanded_key.push_back(key[i % key.size()] ^ iv[i]);
        }
        
        // Simple XOR encryption (for demonstration only)
        for (size_t i = 0; i < result.size(); i++) {
            result[i] ^= expanded_key[i % expanded_key.size()];
        }
        
        return result;
    }

public:
    AES(const std::vector<uint8_t>& symmetric_key) {
        if (symmetric_key.size() != KEY_SIZE) {
            throw std::invalid_argument("Invalid key size for AES-256");
        }
        key = symmetric_key;
    }
    
    // Generate a random AES key
    static std::vector<uint8_t> generateKey() {
        return SecureRandom::random_bytes(KEY_SIZE); // Generate 128-byte key
    }
    
    // Generate a random initialization vector
    static std::vector<uint8_t> generateIV() {
        return SecureRandom::random_bytes(BLOCK_SIZE);
    }
    
    // Encrypt a message
    std::vector<uint8_t> encrypt(const std::string& message) const {
        std::vector<uint8_t> plaintext(message.begin(), message.end());
        std::vector<uint8_t> iv = generateIV();
        
        // In production, use a proper AES implementation with authenticated encryption
        std::vector<uint8_t> ciphertext = simpleXorEncrypt(plaintext, iv);
        
        // Prepend IV to ciphertext
        std::vector<uint8_t> result = iv;
        result.insert(result.end(), ciphertext.begin(), ciphertext.end());
        
        return result;
    }
    
    // Decrypt a message
    std::string decrypt(const std::vector<uint8_t>& encrypted_data) const {
        if (encrypted_data.size() <= BLOCK_SIZE) {
            throw std::invalid_argument("Invalid encrypted data");
        }
        
        // Extract IV from the beginning of the encrypted data
        std::vector<uint8_t> iv(encrypted_data.begin(), encrypted_data.begin() + BLOCK_SIZE);
        
        // Extract ciphertext
        std::vector<uint8_t> ciphertext(encrypted_data.begin() + BLOCK_SIZE, encrypted_data.end());
        
        // Decrypt
        std::vector<uint8_t> plaintext = simpleXorEncrypt(ciphertext, iv);
        
        return std::string(plaintext.begin(), plaintext.end());
    }
    
    // Get key as hex string for debugging
    std::string getKeyHex() const {
        std::stringstream ss;
        ss << std::hex << std::setfill('0');
        for (uint8_t byte : key) {
            ss << std::setw(2) << static_cast<int>(byte);
        }
        return ss.str();
    }
};

// --- Lattice-Based Key Exchange ---
class LatticeCrypto {
private:
    const int n = 1024;               // Polynomial degree
    const int q = 12289;              // NTT-friendly prime modulus (q = 12*1024+1)
    const int message_scaling = q / 2;  // Scaling factor for message embedding
    const double sigma_noise = 0.1;     // Standard deviation for Gaussian noise

    // Polynomials stored as vectors
    std::vector<int> s;
    std::vector<int> e;
    std::vector<int> a;
    std::vector<int> b;

    // Ensure x is in [0, q-1]
    int mod(int x) {
        return ModularArithmetic::mod(x, q);
    }

    // Generate discrete Gaussian noise
    void generate_discrete_gaussian_noise(std::vector<int>& noise, double sigma) {
        for (int i = 0; i < n; i++) {
            noise[i] = SecureRandom::discrete_gaussian_sample(sigma);
        }
    }

    // --- NTT Implementation ---
    void ntt(std::vector<int>& a, bool invert) {
        int size = a.size();
        // Bit-reversal permutation
        for (int i = 1, j = 0; i < size; i++) {
            int bit = size >> 1;
            for (; j & bit; bit >>= 1)
                j -= bit;
            j += bit;
            if (i < j)
                std::swap(a[i], a[j]);
        }

        // Using 11 as a primitive n-th root of unity modulo q
        for (int len = 2; len <= size; len <<= 1) {
            int wlen = ModularArithmetic::modexp(11, size / len, q);
            if (invert)
                wlen = ModularArithmetic::modinv(wlen, q);
            for (int i = 0; i < size; i += len) {
                int w = 1;
                for (int j = 0; j < len/2; j++) {
                    int u = a[i+j];
                    int v = (int)((1LL * a[i+j+len/2] * w) % q);
                    a[i+j] = mod(u + v);
                    a[i+j+len/2] = mod(u - v);
                    w = (int)((1LL * w * wlen) % q);
                }
            }
        }
        if (invert) {
            int n_inv = ModularArithmetic::modinv(size, q);
            for (int &x : a)
                x = (int)((1LL * x * n_inv) % q);
        }
    }

    // Cyclic convolution via NTT
    void cyclic_multiply(const std::vector<int>& poly1, const std::vector<int>& poly2, std::vector<int>& result) {
        std::vector<int> fa = poly1;
        std::vector<int> fb = poly2;
        ntt(fa, false);
        ntt(fb, false);
        for (int i = 0; i < n; i++) {
            fa[i] = (int)((1LL * fa[i] * fb[i]) % q);
        }
        ntt(fa, true);
        for (int i = 0; i < n; i++) {
            result[i] = mod(fa[i]);
        }
    }

    void poly_add(const std::vector<int>& poly1, const std::vector<int>& poly2, std::vector<int>& result) {
        for (int i = 0; i < n; i++) {
            result[i] = mod(poly1[i] + poly2[i]);
        }
    }

    void poly_sub(const std::vector<int>& poly1, const std::vector<int>& poly2, std::vector<int>& result) {
        for (int i = 0; i < n; i++) {
            result[i] = mod(poly1[i] - poly2[i]);
        }
    }

    // Center the coefficients in the range (-q/2, q/2)
    void center_coeffs(std::vector<int>& poly) {
        for (int i = 0; i < n; i++) {
            if (poly[i] > q / 2)
                poly[i] -= q;
        }
    }

public:
    LatticeCrypto() : 
        s(n, 0), e(n, 0), a(n, 0), b(n, 0)
    {
        generate_discrete_gaussian_noise(s, sigma_noise);
        generate_discrete_gaussian_noise(e, sigma_noise);

        // Use a cryptographically secure method for choosing a
        for (int i = 0; i < n; i++) {
            a[i] = SecureRandom::uniform_int(0, q - 1);
        }

        std::vector<int> temp(n, 0);
        cyclic_multiply(a, s, temp);
        poly_add(temp, e, b);
    }

    // Get public key components (a, b)
    std::pair<std::vector<int>, std::vector<int>> getPublicKey() const {
        return {a, b};
    }
    
    // Encrypt a symmetric key (represented as byte vector)
    std::pair<std::vector<int>, std::vector<int>> encryptSymmetricKey(const std::vector<uint8_t>& sym_key) {
        std::vector<int> m(n, 0);

        // Embed symmetric key into polynomial coefficients
        // Each byte goes into 8 consecutive coefficients
        size_t bits_used = 0;
        for (uint8_t byte : sym_key) {
            for (int bit = 0; bit < 8 && bits_used < static_cast<size_t>(n); bit++, bits_used++) {
                m[bits_used] = ((byte >> bit) & 1) ? message_scaling : 0;
            }
        }

        std::vector<int> e1(n, 0), e2(n, 0), r(n, 0);
        generate_discrete_gaussian_noise(e1, sigma_noise);
        generate_discrete_gaussian_noise(e2, sigma_noise);
        generate_discrete_gaussian_noise(r, sigma_noise);

        std::vector<int> u(n, 0), v(n, 0);
        std::vector<int> temp(n, 0);

        cyclic_multiply(a, r, temp);
        poly_add(temp, e1, u);
        
        cyclic_multiply(b, r, temp);
        poly_add(temp, e2, v);
        poly_add(v, m, v);

        return {u, v};
    }

    // Decrypt the symmetric key
    std::vector<uint8_t> decryptSymmetricKey(const std::vector<int>& u, const std::vector<int>& v, size_t key_size) {
        std::vector<int> md(n, 0);
        std::vector<int> temp(n, 0);

        cyclic_multiply(s, u, temp);
        poly_sub(v, temp, md);
        center_coeffs(md);

        std::vector<uint8_t> recovered_key(key_size, 0);

        // Extract bits from polynomial coefficients and reconstruct bytes
        for (size_t byte_idx = 0; byte_idx < key_size; byte_idx++) {
            uint8_t byte_val = 0;
            for (int bit = 0; bit < 8; bit++) {
                size_t coef_idx = byte_idx * 8 + bit;
                if (coef_idx >= static_cast<size_t>(n)) break;

                if (abs(md[coef_idx]) >= message_scaling / 2) {
                    byte_val |= (1 << bit);
                }
            }
            recovered_key[byte_idx] = byte_val;
        }

        return recovered_key;
    }
    
    // Serialize public key for transmission
    static std::string serializePublicKey(const std::pair<std::vector<int>, std::vector<int>>& pubKey) {
        const auto& [a, b] = pubKey;
        std::string result = std::to_string(a.size()) + "|";
        
        // Serialize a polynomial
        for (int val : a) {
            result += std::to_string(val) + ",";
        }
        result += "|";
        
        // Serialize b polynomial
        for (int val : b) {
            result += std::to_string(val) + ",";
        }
        
        return result;
    }
    
    // Deserialize public key after receiving
    static std::pair<std::vector<int>, std::vector<int>> deserializePublicKey(const std::string& serialized) {
        std::vector<std::string> parts;
        size_t start = 0, end = 0;
        while ((end = serialized.find('|', start)) != std::string::npos) {
            parts.push_back(serialized.substr(start, end - start));
            start = end + 1;
        }
        
        int poly_size = std::stoi(parts[0]);
        
        // Deserialize a polynomial
        std::vector<int> a;
        std::string a_chunk = parts[1];
        size_t pos = 0;
        std::string token;
        while ((pos = a_chunk.find(',')) != std::string::npos) {
            token = a_chunk.substr(0, pos);
            if (!token.empty()) {
                a.push_back(std::stoi(token));
            }
            a_chunk.erase(0, pos + 1);
        }
        
        // Deserialize b polynomial
        std::vector<int> b;
        std::string b_chunk = serialized.substr(start);
        pos = 0;
        while ((pos = b_chunk.find(',')) != std::string::npos) {
            token = b_chunk.substr(0, pos);
            if (!token.empty()) {
                b.push_back(std::stoi(token));
            }
            b_chunk.erase(0, pos + 1);
        }
        
        return {a, b};
    }
    
    // Serialize encrypted data for transmission
    static std::string serializeEncryptedData(const std::pair<std::vector<int>, std::vector<int>>& encrypted) {
        const auto& [u, v] = encrypted;
        std::string result = std::to_string(u.size()) + "|";
        
        // Serialize u vector
        for (int val : u) {
            result += std::to_string(val) + ",";
        }
        result += "|";
        
        // Serialize v vector
        for (int val : v) {
            result += std::to_string(val) + ",";
        }
        
        return result;
    }
    
    // Deserialize encrypted data after receiving
    static std::pair<std::vector<int>, std::vector<int>> deserializeEncryptedData(const std::string& serialized) {
        std::vector<std::string> parts;
        size_t start = 0, end = 0;
        while ((end = serialized.find('|', start)) != std::string::npos) {
            parts.push_back(serialized.substr(start, end - start));
            start = end + 1;
        }
        
        int vec_size = std::stoi(parts[0]);
        
        // Deserialize u vector
        std::vector<int> u;
        std::string u_chunk = parts[1];
        size_t pos = 0;
        std::string token;
        while ((pos = u_chunk.find(',')) != std::string::npos) {
            token = u_chunk.substr(0, pos);
            if (!token.empty()) {
                u.push_back(std::stoi(token));
            }
            u_chunk.erase(0, pos + 1);
        }
        
        // Deserialize v vector
        std::vector<int> v;
        std::string v_chunk = serialized.substr(start);
        pos = 0;
        while ((pos = v_chunk.find(',')) != std::string::npos) {
            token = v_chunk.substr(0, pos);
            if (!token.empty()) {
                v.push_back(std::stoi(token));
            }
            v_chunk.erase(0, pos + 1);
        }
        
        return {u, v};
    }
};

// --- Chat Application Cryptography Manager ---
class ChatCryptoManager {
private:
    // Map of user IDs to their lattice crypto objects
    std::unordered_map<std::string, std::unique_ptr<LatticeCrypto>> user_crypto;
    
    // Map of chat session IDs to their AES symmetric keys
    std::unordered_map<std::string, std::vector<uint8_t>> session_keys;
    
    // Generate a unique session ID for a chat between two users
    std::string generateSessionId(const std::string& user1, const std::string& user2) {
        return user1 < user2 ? user1 + "|" + user2 : user2 + "|" + user1; // Use a delimiter for clarity
    }

public:
    ChatCryptoManager() = default;
    
    // Register a new user with lattice-based crypto
    void registerUser(const std::string& userId) {
        if (user_crypto.find(userId) != user_crypto.end()) {
            throw std::runtime_error("User already registered");
        }
        
        user_crypto[userId] = std::make_unique<LatticeCrypto>();
    }
    
    // Get public key for a user
    std::string getUserPublicKey(const std::string& userId) {
        auto it = user_crypto.find(userId);
        if (it == user_crypto.end()) {
            throw std::runtime_error("User not registered");
        }
        
        auto pubKey = it->second->getPublicKey();
        return LatticeCrypto::serializePublicKey(pubKey);
    }
    
    // Establish a secure session between users
    void establishSession(const std::string& sender, const std::string& receiver, const std::string& receiverPublicKey) {
        auto it = user_crypto.find(sender);
        if (it == user_crypto.end()) {
            throw std::runtime_error("Sender not registered");
        }
        
        // Deserialize receiver's public key
        auto pubKey = LatticeCrypto::deserializePublicKey(receiverPublicKey);
        
        // Generate a new symmetric key
        std::vector<uint8_t> symmetricKey = AES::generateKey();
        
        // Create session ID
        std::string sessionId = generateSessionId(sender, receiver);
        
        // Store symmetric key
        session_keys[sessionId] = symmetricKey;
    }
    
    // Generate encrypted symmetric key for sending to another user
    std::string generateEncryptedSymmetricKey(const std::string& sender, const std::string& receiver, const std::string& receiverPublicKey) {
        std::string sessionId = generateSessionId(sender, receiver);
        
        // Check if symmetric key exists
        if (session_keys.find(sessionId) == session_keys.end()) {
            // Generate new symmetric key if needed
            establishSession(sender, receiver, receiverPublicKey);
        }
        
        // Get symmetric key
        std::vector<uint8_t>& symmetricKey = session_keys[sessionId];
        
        // Deserialize receiver's public key
        auto pubKey = LatticeCrypto::deserializePublicKey(receiverPublicKey);
        
        // Create temporary LatticeCrypto object with receiver's public key
        LatticeCrypto tempCrypto;
        
        // Encrypt the symmetric key using receiver's public key
        auto encryptedKey = tempCrypto.encryptSymmetricKey(symmetricKey);
        
        // Serialize the encrypted key
        return LatticeCrypto::serializeEncryptedData(encryptedKey);
    }
    
    // Receive and decrypt a symmetric key from another user
    void receiveEncryptedSymmetricKey(const std::string& receiver, const std::string& sender, const std::string& encryptedKeyData) {
        auto it = user_crypto.find(receiver);
        if (it == user_crypto.end()) {
            throw std::runtime_error("Receiver not registered");
        }
        
        // Deserialize the encrypted key
        auto encryptedKey = LatticeCrypto::deserializeEncryptedData(encryptedKeyData);
        
        // Decrypt the symmetric key
        constexpr size_t AES_KEY_SIZE = 128; // 1024-bit key
        std::vector<uint8_t> symmetricKey = it->second->decryptSymmetricKey(encryptedKey.first, encryptedKey.second, AES_KEY_SIZE);
        
        // Create session ID
        std::string sessionId = generateSessionId(sender, receiver);
        
        // Store symmetric key
        session_keys[sessionId] = symmetricKey;
    }
    
    // Encrypt a message for a specific session using symmetric encryption
    std::vector<uint8_t> encryptMessage(const std::string& sender, const std::string& receiver, const std::string& message) {
        std::string sessionId = generateSessionId(sender, receiver);
        
        auto it = session_keys.find(sessionId);
        if (it == session_keys.end()) {
            throw std::runtime_error("Secure session not established");
        }
        
        // Create AES encryptor with session key
        AES aes(it->second);
        
        // Encrypt the message
        return aes.encrypt(message);
    }
    
    // Serialize encrypted message for transmission
    static std::string serializeEncryptedMessage(const std::vector<uint8_t>& encrypted) {
        std::stringstream ss;
        ss << std::hex << std::setfill('0');
        for (uint8_t byte : encrypted) {
            ss << std::setw(2) << static_cast<int>(byte);
        }
        return ss.str();
    }
    
    // Deserialize encrypted message after receiving
    static std::vector<uint8_t> deserializeEncryptedMessage(const std::string& serialized) {
        std::vector<uint8_t> result;
        for (size_t i = 0; i < serialized.length(); i += 2) {
            std::string byteStr = serialized.substr(i, 2);
            uint8_t byte = static_cast<uint8_t>(std::stoi(byteStr, nullptr, 16));
            result.push_back(byte);
        }
        return result;
    }
    
    // Decrypt a message from a specific session
    std::string decryptMessage(const std::string& receiver, const std::string& sender, const std::string& encryptedMessageStr) {
        std::string sessionId = generateSessionId(receiver, sender);
        
        auto it = session_keys.find(sessionId);
        if (it == session_keys.end()) {
            throw std::runtime_error("Secure session not established");
        }
        
        // Deserialize the encrypted message
        std::vector<uint8_t> encryptedMessage = deserializeEncryptedMessage(encryptedMessageStr);
        
        // Create AES decryptor with session key
        AES aes(it->second);
        
        // Decrypt the message
        return aes.decrypt(encryptedMessage);
    }
    
    // Check if a secure session exists between users
    bool hasSession(const std::string& user1, const std::string& user2) {
        std::string sessionId = generateSessionId(user1, user2);
        return session_keys.find(sessionId) != session_keys.end();
    }
    
    // Get session key in hex format (for debugging)
    std::string getSessionKeyHex(const std::string& user1, const std::string& user2) {
        std::string sessionId = generateSessionId(user1, user2);
        auto it = session_keys.find(sessionId);
        if (it == session_keys.end()) {
            throw std::runtime_error("Secure session not established");
        }
        
        std::stringstream ss;
        ss << std::hex << std::setfill('0');
        for (uint8_t byte : it->second) {
            ss << std::setw(2) << static_cast<int>(byte);
        }
        return ss.str();
    }
    
    // Revoke a user's session
    void revokeUser(const std::string& userId) {
        // Remove user crypto
        user_crypto.erase(userId);
        
        // Remove all sessions involving this user
        std::vector<std::string> sessionsToRemove;
        
        for (const auto& [sessionId, _] : session_keys) {
            if (sessionId.find(userId) != std::string::npos) {
                sessionsToRemove.push_back(sessionId);
            }
        }
        
        for (const auto& id : sessionsToRemove) {
            session_keys.erase(id);
        }
    }
};

// Example usage in a chat application backend
int main() {
    try {
        // Create a crypto manager
        ChatCryptoManager manager;
        
        // Register users
        manager.registerUser("alice");
        manager.registerUser("bob");
        
        // Get public keys
        std::string alicePublicKey = manager.getUserPublicKey("alice");
        std::string bobPublicKey = manager.getUserPublicKey("bob");
        
        std::cout << "Protocol beginning..." << std::endl;
        
        // Alice generates an encrypted symmetric key for Bob
        std::string encryptedKeyFromAlice = manager.generateEncryptedSymmetricKey("alice", "bob", bobPublicKey);
        
        // Bob receives and decrypts the symmetric key
        manager.receiveEncryptedSymmetricKey("bob", "alice", encryptedKeyFromAlice);
        
        // Now Bob generates his own encrypted key for Alice
        std::string encryptedKeyFromBob = manager.generateEncryptedSymmetricKey("bob", "alice", alicePublicKey);
        
        // Alice receives and decrypts Bob's key
        manager.receiveEncryptedSymmetricKey("alice", "bob", encryptedKeyFromBob);
        
        // Verify both sides have established the session
        std::cout << "Session established: " << (manager.hasSession("alice", "bob") ? "Yes" : "No") << std::endl;
        
        // For debugging purposes, check if they have the same key
        std::string aliceKey = manager.getSessionKeyHex("alice", "bob");
        std::string bobKey = manager.getSessionKeyHex("bob", "alice");
        std::cout << "Alice's session key: " << aliceKey << std::endl;
        std::cout << "Bob's session key: " << bobKey << std::endl;
        std::cout << "Keys match: " << (aliceKey == bobKey ? "Yes" : "No") << std::endl;
        
        // Alice encrypts a message for Bob using symmetric encryption
        std::string aliceMessage = "Hi Bob, can we talk about the project?";
        std::vector<uint8_t> encryptedMessageBytes = manager.encryptMessage("alice", "bob", aliceMessage);
        std::string encryptedMessage = ChatCryptoManager::serializeEncryptedMessage(encryptedMessageBytes);
        
        // Bob decrypts Alice's message
        std::string decryptedMessage = manager.decryptMessage("bob", "alice", encryptedMessage);
        
        // Verify the result
        std::cout << "\nOriginal message from Alice: " << aliceMessage << std::endl;
        std::cout << "Decrypted message by Bob: " << decryptedMessage << std::endl;

        return 0; // Ensure main function ends properly
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }
}