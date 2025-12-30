#include <iostream>
#include <string>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <cstring>
#include <openssl/evp.h>
#include <openssl/err.h>

using namespace std;

// Same key & IV as server!
unsigned char KEY[32] = { /* same as server */ };
unsigned char IV[16]  = { /* same as server */ };

// ─── AES helpers (copy from server) ──────────────────────────────────────────
// (paste encrypt + decrypt + handle_openssl_error functions here)

int aes_gcm_encrypt(const string& plaintext, unsigned char* ciphertext);
int aes_gcm_decrypt(const unsigned char* ciphertext, int ct_len, string& plaintext);
void handle_openssl_error();

// ─── Main ─────────────────────────────────────────────────────────────────────
int main(int argc, char** argv) {
    if (argc < 4) {
        cerr << "Usage: ./client <server_ip> <port> <message>\n";
        cerr << "Example: ./client 127.0.0.1 65432 SetA-Two\n";
        return 1;
    }

    string server_ip = argv[1];
    int port         = stoi(argv[2]);
    string message   = argv[3];

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) { perror("socket"); return 1; }

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port   = htons(port);
    inet_pton(AF_INET, server_ip.c_str(), &addr.sin_addr);

    if (connect(sock, (sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("connect"); return 1;
    }

    cout << "Connected to " << server_ip << ":" << port << endl;

    // Encrypt & send request
    char enc[2048];
    int elen = aes_gcm_encrypt(message, (unsigned char*)enc);
    send(sock, enc, elen, 0);

    // Receive responses
    char buffer[2048];
    ssize_t n;

    cout << "\nReceived:\n";
    cout << string(40, '-') << "\n";

    while ((n = recv(sock, buffer, sizeof(buffer), 0)) > 0) {
        string plaintext;
        aes_gcm_decrypt((unsigned char*)buffer, n, plaintext);
        cout << plaintext << endl;
    }

    close(sock);
    return 0;
}
