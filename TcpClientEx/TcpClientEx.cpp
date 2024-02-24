// TcpClientEx.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include "libs/tcp_client.h"

int main()
{
    auto client = new tcp::client();
    if (client->create_socket()) {
        std::string resp = client->send_message("Hey");
        std::cout << resp << std::endl;
    }
}