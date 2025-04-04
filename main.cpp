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

// --- Diffie-Hellman Key Exchange ---
class DiffieHellman {
private:
    uint64_t p;  // Large prime for Diffie-Hellman
    uint64_t g;  // Generator
    uint64_t private_key;
    uint64_t public_key;

    uint64_t mod_exp(uint64_t base, uint64_t exp, uint64_t mod) const {
    uint64_t result = 1;
    while (exp > 0) {
        if (exp & 1) result = (result * base) % mod;
        base = (base * base) % mod;
        exp >>= 1;
    }
    return result;
}


public:
    DiffieHellman(uint64_t prime, uint64_t generator) : p(prime), g(generator) {
        // Use a secure random 64-bit integer for the private key
        uint64_t rnd = SecureRandom::random_u64();
        // Choose private key in [1, p-2]
        private_key = (rnd % (p - 2)) + 1;
        public_key = mod_exp(g, private_key, p);
    }

    uint64_t getPublicKey() const {
        return public_key;
    }

    uint64_t computeSharedSecret(uint64_t receivedPublicKey) const {
        if (receivedPublicKey <= 1 || receivedPublicKey >= p) {
            throw std::invalid_argument("Invalid public key received");
        }
        return mod_exp(receivedPublicKey, private_key, p);
    }
    
    // Added for serialization in chat apps
    std::string getPublicKeyAsString() const {
        return std::to_string(public_key);
    }
};

// --- Lattice-Based Encryption using NTT ---
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

    uint64_t shared_secret_key; // Derived from Diffie-Hellman

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
    LatticeCrypto(uint64_t shared_key) : 
        shared_secret_key(shared_key), 
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

    // Encrypt a 64-bit message into a pair of polynomials
    std::pair<std::vector<int>, std::vector<int>> encrypt(uint64_t message_int) {
        std::vector<int> m(n, 0);
        std::bitset<64> message_bin(message_int);
        for (int i = 0; i < 64; i++) {
            m[i] = message_bin[i] ? message_scaling : 0;
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

    // Encrypt a string message
    std::pair<std::vector<std::vector<int>>, std::vector<std::vector<int>>> encryptString(const std::string& message) {
        std::vector<std::vector<int>> u_values;
        std::vector<std::vector<int>> v_values;
        
        // Process message in 8-byte (64-bit) chunks
        for (size_t i = 0; i < message.length(); i += 8) {
            uint64_t chunk = 0;
            // Pack up to 8 bytes into a 64-bit integer
            for (size_t j = 0; j < 8 && i + j < message.length(); ++j) {
                chunk |= (static_cast<uint64_t>(message[i + j]) << (j * 8));
            }
            
            auto [u, v] = encrypt(chunk);
            u_values.push_back(u);
            v_values.push_back(v);
        }
        
        return {u_values, v_values};
    }

    // Decrypt a single 64-bit message
    uint64_t decrypt(const std::vector<int>& u, const std::vector<int>& v) {
        std::vector<int> md(n, 0);
        std::vector<int> temp(n, 0);

        cyclic_multiply(s, u, temp);
        poly_sub(v, temp, md);
        center_coeffs(md);

        std::bitset<64> recovered;
        for (int i = 0; i < 64; i++) {
            recovered[i] = (abs(md[i]) >= message_scaling / 2) ? 1 : 0;
        }
        return recovered.to_ullong();
    }
    
    // Decrypt a string message
    std::string decryptString(const std::vector<std::vector<int>>& u_values, 
                            const std::vector<std::vector<int>>& v_values) {
        std::string result;
        
        for (size_t i = 0; i < u_values.size(); ++i) {
            uint64_t decrypted_chunk = decrypt(u_values[i], v_values[i]);
            
            // Extract up to 8 bytes from the 64-bit integer
            for (size_t j = 0; j < 8; ++j) {
                char c = static_cast<char>((decrypted_chunk >> (j * 8)) & 0xFF);
                if (c != '\0') { // Stop at null terminator
                    result.push_back(c);
                }
            }
        }
        
        return result;
    }
    
    // Serialize the encrypted data for transmission
    static std::string serializeEncryptedData(
        const std::vector<std::vector<int>>& u_values,
        const std::vector<std::vector<int>>& v_values) {
        // Simple serialization - this should be improved in production
        std::string result;
        
        // Format: num_chunks|u_size|v_size|u_values|v_values
        result += std::to_string(u_values.size()) + "|";
        result += std::to_string(u_values[0].size()) + "|";
        result += std::to_string(v_values[0].size()) + "|";
        
        for (const auto& u : u_values) {
            for (int val : u) {
                result += std::to_string(val) + ",";
            }
            result += "|";
        }
        
        for (const auto& v : v_values) {
            for (int val : v) {
                result += std::to_string(val) + ",";
            }
            result += "|";
        }
        
        return result;
    }
    
    // Deserialize the encrypted data after receiving
    static std::pair<std::vector<std::vector<int>>, std::vector<std::vector<int>>> 
    deserializeEncryptedData(const std::string& serialized) {
        // Simple deserialization - this should be improved in production
        std::vector<std::vector<int>> u_values;
        std::vector<std::vector<int>> v_values;
        
        std::vector<std::string> parts;
        size_t start = 0, end = 0;
        while ((end = serialized.find('|', start)) != std::string::npos) {
            parts.push_back(serialized.substr(start, end - start));
            start = end + 1;
        }
        
        int num_chunks = std::stoi(parts[0]);
        int u_size = std::stoi(parts[1]);
        int v_size = std::stoi(parts[2]);
        
        int part_idx = 3;
        
        // Read u values
        for (int i = 0; i < num_chunks; i++) {
            std::vector<int> u;
            std::string& chunk = parts[part_idx++];
            
            size_t pos = 0;
            std::string token;
            while ((pos = chunk.find(',')) != std::string::npos) {
                token = chunk.substr(0, pos);
                if (!token.empty()) {
                    u.push_back(std::stoi(token));
                }
                chunk.erase(0, pos + 1);
            }
            
            u_values.push_back(u);
        }
        
        // Read v values
        for (int i = 0; i < num_chunks; i++) {
            std::vector<int> v;
            std::string& chunk = parts[part_idx++];
            
            size_t pos = 0;
            std::string token;
            while ((pos = chunk.find(',')) != std::string::npos) {
                token = chunk.substr(0, pos);
                if (!token.empty()) {
                    v.push_back(std::stoi(token));
                }
                chunk.erase(0, pos + 1);
            }
            
            v_values.push_back(v);
        }
        
        return {u_values, v_values};
    }
};

// --- Chat Application Cryptography Manager ---
class ChatCryptoManager {
private:
    // Map of user IDs to their DiffieHellman objects
    std::unordered_map<std::string, std::unique_ptr<DiffieHellman>> user_keys;
    
    // Map of chat session IDs to their LatticeCrypto objects
    std::unordered_map<std::string, std::unique_ptr<LatticeCrypto>> session_cryptos;
    
    // Cache of shared secrets between users
    std::unordered_map<std::string, uint64_t> shared_secrets;
    
    // Default Diffie-Hellman parameters
    static constexpr uint64_t DEFAULT_PRIME = 104729;
    static constexpr uint64_t DEFAULT_GENERATOR = 2;
    
    // Generate a unique session ID for a chat between two users
    std::string generateSessionId(const std::string& user1, const std::string& user2) {
        return user1 < user2 ? user1 + "" + user2 : user2 + "" + user1;
    }

public:
    ChatCryptoManager() = default;
    
    // Register a new user
    void registerUser(const std::string& userId) {
        if (user_keys.find(userId) != user_keys.end()) {
            throw std::runtime_error("User already registered");
        }
        
        user_keys[userId] = std::make_unique<DiffieHellman>(DEFAULT_PRIME, DEFAULT_GENERATOR);
    }
    
    // Get public key for a user
    std::string getUserPublicKey(const std::string& userId) {
        auto it = user_keys.find(userId);
        if (it == user_keys.end()) {
            throw std::runtime_error("User not registered");
        }
        
        return it->second->getPublicKeyAsString();
    }
    
    // Establish a secure session between users
    void establishSession(const std::string& user1, const std::string& user2, uint64_t receivedPublicKey) {
        auto it = user_keys.find(user1);
        if (it == user_keys.end()) {
            throw std::runtime_error("User not registered");
        }
        
        // Compute shared secret
        uint64_t shared_secret = it->second->computeSharedSecret(receivedPublicKey);
        
        // Create session ID
        std::string sessionId = generateSessionId(user1, user2);
        
        // Store shared secret
        shared_secrets[sessionId] = shared_secret;
        
        // Create LatticeCrypto object for this session
        session_cryptos[sessionId] = std::make_unique<LatticeCrypto>(shared_secret);
    }
    
    // Encrypt a message for a specific session
    std::string encryptMessage(const std::string& user1, const std::string& user2, const std::string& message) {
        std::string sessionId = generateSessionId(user1, user2);
        
        auto it = session_cryptos.find(sessionId);
        if (it == session_cryptos.end()) {
            throw std::runtime_error("Secure session not established");
        }
        
        // Encrypt the message
        auto [u_values, v_values] = it->second->encryptString(message);
        
        // Serialize the encrypted data
        return LatticeCrypto::serializeEncryptedData(u_values, v_values);
    }
    
    // Decrypt a message from a specific session
    std::string decryptMessage(const std::string& user1, const std::string& user2, const std::string& encryptedMessage) {
        std::string sessionId = generateSessionId(user1, user2);
        
        auto it = session_cryptos.find(sessionId);
        if (it == session_cryptos.end()) {
            throw std::runtime_error("Secure session not established");
        }
        
        // Deserialize the encrypted data
        auto [u_values, v_values] = LatticeCrypto::deserializeEncryptedData(encryptedMessage);
        
        // Decrypt the message
        return it->second->decryptString(u_values, v_values);
    }
    
    // Check if a secure session exists between users
    bool hasSession(const std::string& user1, const std::string& user2) {
        std::string sessionId = generateSessionId(user1, user2);
        return session_cryptos.find(sessionId) != session_cryptos.end();
    }
    
    // Revoke a user's session
    void revokeUser(const std::string& userId) {
        // Remove user key
        user_keys.erase(userId);
        
        // Remove all sessions involving this user
        std::vector<std::string> sessionsToRemove;
        
        for (const auto& [sessionId, _] : session_cryptos) {
            if (sessionId.find(userId) != std::string::npos) {
                sessionsToRemove.push_back(sessionId);
            }
        }
        
        for (const auto& id : sessionsToRemove) {
            session_cryptos.erase(id);
            shared_secrets.erase(id);
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
        
        // Establish secure session (in a real app, these would be exchanged over the network)
        manager.establishSession("alice", "bob", std::stoull(bobPublicKey));
        manager.establishSession("bob", "alice", std::stoull(alicePublicKey));
        
        // Encrypt a message
        std::string originalMessage = "Hello, this is a secure chat message!";
        std::string encryptedMessage = manager.encryptMessage("alice", "bob", originalMessage);
        
        // Decrypt the message
        std::string decryptedMessage = manager.decryptMessage("bob", "alice", encryptedMessage);
        
        // Verify the result
        std::cout << "Original message: " << originalMessage << std::endl;
        std::cout << "Decrypted message: " << decryptedMessage << std::endl;
        std::cout << "Success: " << (originalMessage == decryptedMessage ? "Yes" : "No") << std::endl;
        
        // Example of a full chat session
        std::cout << "\n--- Example Chat Session ---\n";
        
        // Alice sends a message to Bob
        std::string aliceMessage = "Hi Bob, can we talk about the project?";
        std::string encryptedToBoB = manager.encryptMessage("alice", "bob", aliceMessage);
        std::string bobReceived = manager.decryptMessage("bob", "alice", encryptedToBoB);
        std::cout << "Alice: " << bobReceived << std::endl;
        
        // Bob responds to Alice
        std::string bobMessage = "Sure, Alice! What's on your mind?";
        std::string encryptedToAlice = manager.encryptMessage("bob", "alice", bobMessage);
        std::string aliceReceived = manager.decryptMessage("alice", "bob", encryptedToAlice);
        std::cout << "Bob: " << aliceReceived << std::endl;
        
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }
    
    return 0;
}