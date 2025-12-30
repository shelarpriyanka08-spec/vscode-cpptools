#include <iostream>
#include <thread>
#include <vector>
#include <string>
#include <sstream>
#include <map>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <cstring>
#include <openssl/evp.h>
#include <openssl/err.h>

using namespace std;

// ─── Data structure (exactly as in assignment) ───────────────────────────────
map<string, map<string, int>> lookup = {
    {"SetA", {{"One", 1}, {"Two", 2}}},
    {"SetB", {{"Three", 3}, {"Four", 4}}},
    {"SetC", {{"Five", 5}, {"Six", 6}}},
    {"SetD", {{"Seven", 7}, {"Eight", 8}}},
    {"SetE", {{"Nine", 9}, {"Ten", 10}}}
};

// ─── Configurable parameters (can be set via command line or cin) ────────────
string SERVER_IP   = "0.0.0.0";
int    SERVER_PORT = 65432;

// Fixed key & IV (32 + 16 bytes) – CHANGE FOR YOUR SUBMISSION!
unsigned char KEY[32] = {
    '0','1','2','3','4','5','6','7','8','9','0','1','2','3','4','5',
    '6','7','8','9','0','1','2','3','4','5','6','7','8','9','0','1'
};
unsigned char IV[16] = {
    '0','1','2','3','4','5','6','7','8','9','0','1','2','3','4','5'
};

// ─── AES-256-GCM helpers ─────────────────────────────────────────────────────
void handle_openssl_error() {
    ERR_print_errors_fp(stderr);
    exit(1);
}

int aes_gcm_encrypt(const string& plaintext, unsigned char* ciphertext) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) handle_openssl_error();

    int len = 0, total_len = 0;

    EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, KEY, IV);
    EVP_EncryptUpdate(ctx, ciphertext, &len, (unsigned char*)plaintext.data(), plaintext.size());
    total_len += len;

    EVP_EncryptFinal_ex(ctx, ciphertext + len, &len);
    total_len += len;

    // In real code: append 16-byte tag here (omitted for simplicity)
    EVP_CIPHER_CTX_free(ctx);
    return total_len;
}

int aes_gcm_decrypt(const unsigned char* ciphertext, int ct_len, string& plaintext) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) handle_openssl_error();

    int len = 0, total_len = 0;
    unsigned char buffer[2048];

    EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, KEY, IV);
    EVP_DecryptUpdate(ctx, buffer, &len, ciphertext, ct_len);
    total_len += len;

    EVP_DecryptFinal_ex(ctx, buffer + len, &len);
    total_len += len;

    plaintext.assign((char*)buffer, total_len);
    EVP_CIPHER_CTX_free(ctx);
    return total_len;
}

// ─── Get current time string ─────────────────────────────────────────────────
string get_time_str() {
    time_t now = time(nullptr);
    tm* t = localtime(&now);
    char buf[32];
    strftime(buf, sizeof(buf), "%m-%d-%Y %H:%M:%S", t);
    return string(buf);
}

// ─── Handle one client ───────────────────────────────────────────────────────
void handle_client(int client_fd) {
    char buffer[2048];
    ssize_t n;

    while ((n = read(client_fd, buffer, sizeof(buffer))) > 0) {
        string request;
        aes_gcm_decrypt((unsigned char*)buffer, n, request);

        cout << "[Client] Decrypted request: " << request << endl;

        // Parse "SetX-Item"
        size_t pos = request.find('-');
        if (pos == string::npos) {
            string resp = "EMPTY";
            char enc[2048];
            int elen = aes_gcm_encrypt(resp, (unsigned char*)enc);
            write(client_fd, enc, elen);
            continue;
        }

        string set_name  = request.substr(0, pos);
        string item_name = request.substr(pos + 1);

        int repeat = 0;
        auto it = lookup.find(set_name);
        if (it != lookup.end()) {
            auto& inner = it->second;
            auto val_it = inner.find(item_name);
            if (val_it != inner.end()) {
                repeat = val_it->second;
            }
        }

        if (repeat == 0) {
            string resp = "EMPTY";
            char enc[2048];
            int elen = aes_gcm_encrypt(resp, (unsigned char*)enc);
            write(client_fd, enc, elen);
        } else {
            for (int i = 0; i < repeat; ++i) {
                string time_msg = get_time_str();
                char enc[2048];
                int elen = aes_gcm_encrypt(time_msg, (unsigned char*)enc);
                write(client_fd, enc, elen);
                if (i < repeat - 1) sleep(1);
            }
        }
    }

    close(client_fd);
    cout << "Client disconnected." << endl;
}

// ─── Main ─────────────────────────────────────────────────────────────────────
int main() {
    // Optional: let user configure port/key/etc.
    cout << "Enter port (default 65432): ";
    string port_input;
    getline(cin, port_input);
    if (!port_input.empty()) SERVER_PORT = stoi(port_input);

    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) { perror("socket"); exit(1); }

    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    sockaddr_in addr{};
    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = inet_addr(SERVER_IP.c_str());
    addr.sin_port        = htons(SERVER_PORT);

    if (bind(server_fd, (sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("bind"); exit(1);
    }

    if (listen(server_fd, 10) < 0) {
        perror("listen"); exit(1);
    }

    cout << "Server listening on " << SERVER_IP << ":" << SERVER_PORT << " ...\n";

    while (true) {
        sockaddr_in client_addr{};
        socklen_t len = sizeof(client_addr);
        int client_fd = accept(server_fd, (sockaddr*)&client_addr, &len);
        if (client_fd < 0) { perror("accept"); continue; }

        cout << "New client connected.\n";

        thread t(handle_client, client_fd);
        t.detach();  // fire-and-forget (production would use thread pool)
    }

    close(server_fd);
    return 0;
}
