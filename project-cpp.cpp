#include <iostream>
#include <vector>
#include <random>
#include <bitset>
#include <cmath>

using namespace std;

class LatticeCrypto {
private:
    const int n = 1024;                  // Polynomial dimension
    const int q = (1 << 23) - 1;         // Modulus (2^23 - 1)
    const int message_scaling = q / 2;   // Encode 1 as q/2, 0 as 0
    const double sigma_noise = 1.0;      // Standard deviation for Gaussian noise

    vector<int> s, e;  // Secret key and error
    vector<int> a, b;  // Public key

    // --- Utility Functions ---
    int mod(int x, int q) {
        return ((x % q) + q) % q;
    }

    // Generate discrete Gaussian noise using Box-Muller method
    vector<int> discrete_gaussian_noise(int size, double sigma) {
        random_device rd;
        mt19937 gen(rd());
        normal_distribution<double> dist(0.0, sigma);

        vector<int> noise(size);
        for (int i = 0; i < size; i++) {
            noise[i] = round(dist(gen));
        }
        return noise;
    }

    // Cyclic polynomial multiplication in Z_q[x] / (x^n - 1)
    vector<int> cyclic_multiply(const vector<int>& poly1, const vector<int>& poly2) {
        vector<int> result(n, 0);
        vector<int> conv(2 * n - 1, 0);

        // Full convolution
        for (int i = 0; i < n; i++) {
            for (int j = 0; j < n; j++) {
                conv[i + j] = mod(conv[i + j] + poly1[i] * poly2[j], q);
            }
        }

        // Wrap-around for cyclic property
        for (int i = n; i < 2 * n - 1; i++) {
            result[i - n] = mod(conv[i - n] + conv[i], q);
        }
        return result;
    }

    // Polynomial addition modulo q
    vector<int> poly_add(const vector<int>& a, const vector<int>& b) {
        vector<int> result(n);
        for (int i = 0; i < n; i++) {
            result[i] = mod(a[i] + b[i], q);
        }
        return result;
    }

    // Polynomial subtraction modulo q
    vector<int> poly_sub(const vector<int>& a, const vector<int>& b) {
        vector<int> result(n);
        for (int i = 0; i < n; i++) {
            result[i] = mod(a[i] - b[i], q);
        }
        return result;
    }

    // Center coefficients to range [-q/2, q/2]
    vector<int> center_coeffs(const vector<int>& arr) {
        vector<int> centered(n);
        for (int i = 0; i < n; i++) {
            centered[i] = (arr[i] > q / 2) ? arr[i] - q : arr[i];
        }
        return centered;
    }

public:
    // Constructor (Generates keys)
    LatticeCrypto() {
        s = discrete_gaussian_noise(n, sigma_noise);
        e = discrete_gaussian_noise(n, sigma_noise);

        // Public polynomial a (uniformly random in [0, q))
        random_device rd;
        mt19937 gen(rd());
        uniform_int_distribution<int> uniform_dist(0, q - 1);

        a.resize(n);
        for (int i = 0; i < n; i++) {
            a[i] = uniform_dist(gen);
        }

        // Compute public key: b = a * s + e
        b = poly_add(cyclic_multiply(a, s), e);
    }

    // Encrypt a 1024-bit integer
    pair<vector<int>, vector<int>> encrypt(uint64_t message_int) {
        bitset<1024> message_bin(message_int);
        vector<int> m(n, 0);

        // Scale message (bit 1 -> message_scaling, bit 0 -> 0)
        for (int i = 0; i < 1024; i++) {
            m[i] = message_bin[i] * message_scaling;
        }

        // Generate encryption randomness
        vector<int> e1 = discrete_gaussian_noise(n, sigma_noise);
        vector<int> e2 = discrete_gaussian_noise(n, sigma_noise);
        vector<int> r = discrete_gaussian_noise(n, sigma_noise);

        // Compute ciphertext: u = a * r + e1, v = b * r + e2 + m
        vector<int> u = poly_add(cyclic_multiply(a, r), e1);
        vector<int> v = poly_add(poly_add(cyclic_multiply(b, r), e2), m);

        return make_pair(u, v);
    }

    // Decrypt the ciphertext
    uint64_t decrypt(const vector<int>& u, const vector<int>& v) {
        // Compute md = v - s * u
        vector<int> md = poly_sub(v, cyclic_multiply(s, u));

        // Center coefficients
        vector<int> centered_md = center_coeffs(md);

        // Recover bits: If abs(coefficient) < message_scaling / 2, decode as 0, else 1
        bitset<1024> recovered;
        for (int i = 0; i < 1024; i++) {
            recovered[i] = (abs(centered_md[i]) >= message_scaling / 2) ? 1 : 0;
        }

        return recovered.to_ullong();
    }

    // Destructor: Wipe sensitive data
    ~LatticeCrypto() {
        fill(s.begin(), s.end(), 0);
        fill(e.begin(), e.end(), 0);
    }
};

// --- MAIN FUNCTION ---
int main() {
    LatticeCrypto crypto;

    // Generate a random 1024-bit message
    random_device rd;
    mt19937_64 gen(rd());
    uint64_t message = gen();

    // Encrypt the message
    pair<vector<int>, vector<int>> ciphertext = crypto.encrypt(message);
    vector<int> u = ciphertext.first;
    vector<int> v = ciphertext.second;

    // Decrypt the message
    uint64_t decrypted = crypto.decrypt(u, v);

    // Output results
    cout << "Original Message (Hex): " << hex << message << endl;
    cout << "Recovered Message (Hex): " << hex << decrypted << endl;
    cout << "Decryption Successful: " << (message == decrypted ? "Yes" : "No") << endl;

    return 0;
}
