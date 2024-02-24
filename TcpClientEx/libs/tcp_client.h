#pragma once
#include <cstddef>
#include <vector>
#include <iostream>
#include <windows.h>

namespace tcp
{
	class client
	{
		static UINT_PTR cur_socket;
	public:
		bool                   create_socket();
		bool                   connected();
		bool                   disconnect(UINT_PTR socket);
		std::string            send_message(std::string buffer);
	};
}