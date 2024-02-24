#include <iostream>
#include <winsock2.h>
#include <Windows.h>
#include <Ws2tcpip.h>
#include <string>

#include "crypto/aes.h"
#include "crypto/base64.h"
#include "crypto/modes.h"
#include "crypto/filters.h"

#include "oxorany.h"
#include "lazy_importer.hpp"

#include "tcp_client.h"

#pragma comment(lib, "Ws2_32.lib")

UINT_PTR tcp::client::cur_socket;

using namespace CryptoPP;

std::string key = oxorany("LTkRDvqvDrQPHBqbAfcApbZLBoJNczrN");
std::string iv = oxorany("LVnsHhZEoAzyqgSm");

std::string AES_encrypt(const std::string& plaintext) {
    std::string ciphertext;
    try {
        CBC_Mode<AES>::Encryption encryption((CryptoPP::byte*)key.data(), key.size(), (CryptoPP::byte*)iv.data());
        StringSource(plaintext, true,
            new StreamTransformationFilter(encryption,
                new Base64Encoder(
                    new StringSink(ciphertext)
                )
            )
        );
    }
    catch (const CryptoPP::Exception& e) {
        std::cout << e.what() << std::endl;
    }

    return ciphertext;
}

std::string AES_decrypt(const std::string& base64_ciphertext) {
    std::string decryptedText;
    try {
        CBC_Mode<AES>::Decryption decryption((CryptoPP::byte*)key.data(), key.size(), (CryptoPP::byte*)iv.data());

        std::string decoded_ciphertext;
        StringSource ss(base64_ciphertext, true,
            new Base64Decoder(
                new StringSink(decoded_ciphertext)
            )
        );

        StringSource(decoded_ciphertext, true,
            new StreamTransformationFilter(decryption,
                new StringSink(decryptedText)
            )
        );
    }
    catch (const CryptoPP::Exception& e) {
        std::cout << e.what() << std::endl;
    }

    return decryptedText;
}

using namespace std;

bool tcp::client::connected() {
    if (!this->cur_socket) return false;
    return true;
}

bool tcp::client::disconnect(UINT_PTR socket) {
    //if (!this->cur_socket) return true;
    if (socket != NULL) LI_FN(closesocket).safe()(socket);
    LI_FN(WSACleanup).safe()();
    this->cur_socket = NULL;
    return true;
}

bool tcp::client::create_socket()
{
    if (tcp::client::connected()) return true;
    WSADATA wsaData;
    int result = LI_FN(WSAStartup).safe()(MAKEWORD(2, 2), &wsaData);
    if (result != 0) {
        std::cout << "WSAStartup failed" << std::endl;
        return false;
    }

    SOCKET sock = LI_FN(socket).safe()(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) {
        std::cout << "Failed to create socket" << std::endl;
        tcp::client::disconnect(NULL);
        return false;
    }

    sockaddr_in serverAddr;
    result = LI_FN(inet_pton).safe()(AF_INET, oxorany("127.0.0.1"), &serverAddr.sin_addr);
    if (result != 1) {
        std::cout << "Invalid address" << std::endl;
        tcp::client::disconnect(sock);
        return false;
    }
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(3000);

    result = LI_FN(connect).safe()(sock, reinterpret_cast<SOCKADDR*>(&serverAddr), sizeof(serverAddr));
    if (result == SOCKET_ERROR) {
        std::cout << "Failed to connect" << std::endl;
        tcp::client::disconnect(sock);
        return false;
    }
    this->cur_socket = sock;
    return this->cur_socket != NULL;
}

std::string tcp::client::send_message(std::string buffer) {
    if (!tcp::client::connected()) return "";
    SOCKET sock = this->cur_socket;
    std::string enc = AES_encrypt(buffer);
    LI_FN(send).safe()(sock, enc.c_str(), enc.length(), 0);

    char buff[1024];
    int bytes_received = LI_FN(recv).safe()(sock, buff, sizeof(buff) - 1, 0);
    int bufferSize = 0;
    char* newBuffer{};
    if (bytes_received > 0) {
        newBuffer = new char[bytes_received + 1];
        LI_FN(memcpy_s)(newBuffer, bytes_received + 1, buff, bytes_received);
        newBuffer[bytes_received] = '\0';
        bufferSize = bytes_received;
    }
    else if (bytes_received == SOCKET_ERROR) {
        tcp::client::disconnect(sock);
        return "";
    }
    else if (bytes_received == 0) {
        tcp::client::disconnect(sock);
        return "";
    }
    std::string response(newBuffer);
    delete[] newBuffer;

    return AES_decrypt(response).c_str();
}