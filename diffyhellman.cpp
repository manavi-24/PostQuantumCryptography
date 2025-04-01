#include <iostream>
#include <random>
#include <bitset>
#include <cmath>
#include <cstdlib>
#include <cstring>  // For memset

using namespace std;

class DiffieHellman {
private:
    uint64_t p;  // Large prime
    uint64_t g;  // Generator
    uint64_t private_key;
    uint64_t public_key;

public:
    DiffieHellman(uint64_t prime, uint64_t generator) : p(prime), g(generator) {
        random_device rd;
        mt19937_64 gen(rd());
        uniform_int_distribution<uint64_t> dist(1, p - 2);
        
        private_key = dist(gen);  // Choose random private key
        public_key = mod_exp(g, private_key, p);  // Compute public key
    }

    uint64_t getPublicKey() {
        return public_key;
    }

    uint64_t computeSharedSecret(uint64_t receivedPublicKey) {
        return mod_exp(receivedPublicKey, private_key, p);
    }

    uint64_t mod_exp(uint64_t base, uint64_t exp, uint64_t mod) {
        uint64_t result = 1;
        while (exp > 0) {
            if (exp % 2 == 1) result = (result * base) % mod;
            base = (base * base) % mod;
            exp /= 2;
        }
        return result;
    }
};

// Lattice-Based Encryption with Manual Memory Management
class LatticeCrypto {
private:
    const int n = 1024;
    const int q = (1 << 23) - 1;
    const int message_scaling = q / 2;
    const double sigma_noise = 1.0;
    int* s;
    int* e;
    int* a;
    int* b;
    uint64_t shared_secret_key;

    int mod(int x, int q) {
        return ((x % q) + q) % q;
    }

    void generate_discrete_gaussian_noise(int* noise, int size, double sigma) {
        random_device rd;
        mt19937 gen(rd());
        normal_distribution<double> dist(0.0, sigma);
        for (int i = 0; i < size; i++) {
            noise[i] = round(dist(gen));
        }
    }

    void cyclic_multiply(const int* poly1, const int* poly2, int* result) {
        int* conv = new int[2 * n - 1]();
        memset(conv, 0, (2 * n - 1) * sizeof(int));

        for (int i = 0; i < n; i++) {
            for (int j = 0; j < n; j++) {
                conv[i + j] = mod(conv[i + j] + poly1[i] * poly2[j], q);
            }
        }

        for (int i = 0; i < n; i++) {
            result[i] = mod(conv[i] + (i + n < 2 * n - 1 ? conv[i + n] : 0), q);
        }

        delete[] conv;
    }

    void poly_add(const int* a, const int* b, int* result) {
        for (int i = 0; i < n; i++) {
            result[i] = mod(a[i] + b[i], q);
        }
    }

    void poly_sub(const int* a, const int* b, int* result) {
        for (int i = 0; i < n; i++) {
            result[i] = mod(a[i] - b[i], q);
        }
    }

    void center_coeffs(int* arr) {
        for (int i = 0; i < n; i++) {
            arr[i] = (arr[i] > q / 2) ? arr[i] - q : arr[i];
        }
    }

public:
    LatticeCrypto(uint64_t shared_key) : shared_secret_key(shared_key) {
        s = new int[n];
        e = new int[n];
        a = new int[n];
        b = new int[n];

        generate_discrete_gaussian_noise(s, n, sigma_noise);
        generate_discrete_gaussian_noise(e, n, sigma_noise);

        random_device rd;
        mt19937 gen(rd());
        uniform_int_distribution<int> uniform_dist(0, q - 1);
        for (int i = 0; i < n; i++) {
            a[i] = uniform_dist(gen);
        }

        int* temp = new int[n];
        cyclic_multiply(a, s, temp);
        poly_add(temp, e, b);
        delete[] temp;
    }

    ~LatticeCrypto() {
        delete[] s;
        delete[] e;
        delete[] a;
        delete[] b;
    }

    pair<int*, int*> encrypt(uint64_t message_int) {
        int* m = new int[n]();
        bitset<1024> message_bin(message_int);
        for (int i = 0; i < 1024; i++) {
            m[i] = message_bin[i] * message_scaling;
        }

        int* e1 = new int[n];
        int* e2 = new int[n];
        int* r = new int[n];
        generate_discrete_gaussian_noise(e1, n, sigma_noise);
        generate_discrete_gaussian_noise(e2, n, sigma_noise);
        generate_discrete_gaussian_noise(r, n, sigma_noise);

        int* u = new int[n];
        int* v = new int[n];

        int* temp = new int[n];
        cyclic_multiply(a, r, temp);
        poly_add(temp, e1, u);
        
        cyclic_multiply(b, r, temp);
        poly_add(temp, e2, v);
        poly_add(v, m, v);

        delete[] e1;
        delete[] e2;
        delete[] r;
        delete[] m;
        delete[] temp;

        return {u, v};
    }

    uint64_t decrypt(const int* u, const int* v) {
        int* md = new int[n];
        int* centered_md = new int[n];

        int* temp = new int[n];
        cyclic_multiply(s, u, temp);
        poly_sub(v, temp, md);
        center_coeffs(md);

        bitset<1024> recovered;
        for (int i = 0; i < 1024; i++) {
            recovered[i] = (abs(md[i]) >= message_scaling / 2) ? 1 : 0;
        }

        delete[] md;
        delete[] centered_md;
        delete[] temp;
        delete[] u;
        delete[] v;

        return recovered.to_ullong();
    }
};

int main() {
    uint64_t prime = 104729;
    uint64_t generator = 2;

    DiffieHellman alice(prime, generator);
    DiffieHellman bob(prime, generator);

    uint64_t alice_shared_secret = alice.computeSharedSecret(bob.getPublicKey());
    uint64_t bob_shared_secret = bob.computeSharedSecret(alice.getPublicKey());

    cout << "Shared Secret Key: " << alice_shared_secret << endl;

    LatticeCrypto crypto(alice_shared_secret);

    random_device rd;
    mt19937_64 gen(rd());
    uint64_t message = gen();

    auto [u, v] = crypto.encrypt(message);
    uint64_t decrypted = crypto.decrypt(u, v);

    cout << "Original: " << hex << message << "\nRecovered: " << hex << decrypted << "\n";
    cout << "Success: " << (message == decrypted ? "Yes" : "No") << endl;

    return 0;
}
