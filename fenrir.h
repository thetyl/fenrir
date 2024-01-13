// MIT License
// 
// Copyright(c) 2023 Tyl
// 
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software andassociated documentation files(the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, andto permit persons to whom the Software is
// furnished to do so, subject to the following conditions :
// 
// The above copyright notice andthis permission notice shall be included in all
// copies or substantial portions of the Software.
// 
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

#include <iostream>
#include <unordered_map>
#include <string>
#include <sstream>
#include <iomanip>
#include <vector>

// ==================================================
// tcp_socket.h
// ==================================================
#ifdef _WIN32
#include <WinSock2.h>
#include <WS2tcpip.h>
#else
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#include <string.h>
#endif

namespace tcp_socket {

#ifdef _WIN32
	typedef SOCKET TCP_SOCKET;
#else
	typedef int TCP_SOCKET;
#endif

	std::string last_error;

	bool init() {
#ifdef _WIN32
		WSADATA wsa_data;

		if (WSAStartup(MAKEWORD(2, 2), &wsa_data) != 0) {
			last_error = "WSAStartup error";
			return false;
		}
#endif

		return true;
	}

	void close(TCP_SOCKET sock) {
#ifdef _WIN32
		closesocket(sock);
#else
		::close(sock);
#endif
	}

	void free() {
#ifdef _WIN32
		WSACleanup();
#endif
	}

	bool bind(int port, TCP_SOCKET &_sock) {
		_sock = NULL;

		addrinfo hints = {};
		hints.ai_family = AF_INET;
		hints.ai_socktype = SOCK_STREAM;
#ifdef _WIN32
		hints.ai_protocol = IPPROTO_TCP;
#else
		hints.ai_protocol = 0;
#endif
		hints.ai_flags = AI_PASSIVE;

		addrinfo *info;

		if (getaddrinfo(nullptr, std::to_string(port).c_str(), &hints, &info) != 0) {
			last_error = "getaddrinfo failed";
			free();
			return false;
		}

		TCP_SOCKET sock = socket(info->ai_family, info->ai_socktype, info->ai_protocol);

#ifdef _WIN32
		if (sock == INVALID_SOCKET) {
			last_error = WSAGetLastError();
#else
		if (sock == -1) {
			last_error = strerror(errno);
#endif
			freeaddrinfo(info);
			return false;
		}

#ifdef _WIN32
		if (::bind(sock, info->ai_addr, static_cast<int>(info->ai_addrlen)) == SOCKET_ERROR) {
			last_error = WSAGetLastError();
#else
		if (::bind(sock, info->ai_addr, info->ai_addrlen) != 0) {
			last_error = strerror(errno);
#endif
			freeaddrinfo(info);
			close(sock);
			return false;
		}

		freeaddrinfo(info);

		_sock = sock;
		return true;
	}

	bool listen(TCP_SOCKET sock) {
#ifdef _WIN32
		if (::listen(sock, SOMAXCONN) == SOCKET_ERROR) {
			last_error = WSAGetLastError();
#else
		if (::listen(sock, SOMAXCONN) == -1) {
			last_error = strerror(errno);
#endif
			close(sock);
			return false;
		}

		return true;
	}

	bool accept(TCP_SOCKET sock, TCP_SOCKET & _client_sock) {
		TCP_SOCKET client_sock = ::accept(sock, nullptr, nullptr);

#ifdef _WIN32
		if (client_sock == INVALID_SOCKET) {
			last_error = WSAGetLastError();
#else
		if (client_sock == -1) {
			last_error = strerror(errno);
#endif
			return false;
		}

		_client_sock = client_sock;
		return true;
	}

	bool send(TCP_SOCKET sock, const char *buffer, int buffer_len) {
#ifdef _WIN32
		if (::send(sock, buffer, buffer_len, 0) == SOCKET_ERROR) {
			last_error = WSAGetLastError();
#else
		if (write(sock, buffer, buffer_len) == -1) {
			last_error = strerror(errno);
#endif
			return false;
		}

		return true;
	}

	int receive(TCP_SOCKET sock, char *buffer, int buffer_len) {
#ifdef _WIN32
		int num_bytes = recv(sock, buffer, buffer_len, 0);
#else
		int num_bytes = read(sock, buffer, buffer_len);
#endif

		if (num_bytes < 0) {
#ifdef _WIN32
			last_error = WSAGetLastError();
#else
			last_error = strerror(errno);
#endif
		}

		return num_bytes;
	}

	bool select(fd_set * read_set, fd_set * write_set, int *_num_ready) {
		int num_ready = ::select(FD_SETSIZE, read_set, write_set, nullptr, nullptr);

#ifdef _WIN32
		if (num_ready == SOCKET_ERROR) {
			last_error = WSAGetLastError();
#else
		if (num_ready == -1) {
			last_error = strerror(errno);
#endif
			return false;
		}

		if (_num_ready != nullptr) {
			*_num_ready = num_ready;
		}

		return true;
	}
}
// ==================================================
// tcp_socket.h
// ==================================================

using namespace tcp_socket;

#define BUFFER_SIZE 4096

namespace fenrir {

	typedef int SOCKET_ID;

	struct ServerDesc {
		int port = 8080;
		void (*on_connect)(SOCKET_ID socket_id) = nullptr;
		void (*on_message)(SOCKET_ID socket_id, const std::string &message) = nullptr;
		void (*on_disconnect)(SOCKET_ID socket_id) = nullptr;
	};

	struct Socket {
		SOCKET_ID socket_id;
		TCP_SOCKET socket;
		bool handshake = false;
		char buffer[BUFFER_SIZE];
		char send_buffer[BUFFER_SIZE];
	};

	struct Json {
		std::stringstream stream;
		std::vector<bool> first;
	};
	
	struct JsonElement {
		std::string value;
		std::unordered_map<std::string, JsonElement *> fields;
		std::vector<JsonElement *> elements;
	};

	bool read_line_from_buffer(Socket &socket, int num_bytes, std::string &_line, int &_index);
	void parse_request_line(std::string &line, std::string &_method, std::string &_path, std::string &_version);
	void parse_header_line(std::string &line, std::unordered_map<std::string, std::string> &headers);
	bool has_header_value(std::unordered_map<std::string, std::string> &headers, const std::string &name, const std::string &value);
	bool has_header(std::unordered_map<std::string, std::string> &headers, const std::string &name);
	std::string sha1(const std::string &message);
	uint32_t circular_shift_left(uint32_t x, int count);
	std::string base64_encode(const std::string &data);
	bool socket_accept(TCP_SOCKET listen_socket);
	bool socket_receive(Socket *socket);
	bool on_socket_handshake(Socket &socket, int num_bytes);
	bool on_socket_data(Socket &socket, int num_bytes);
	void send(SOCKET_ID socket_id, const std::string &message);
	static void send_socket_data(Socket &socket, uint8_t op_code);
	void to_json(Json &json, const std::string &value);
	void to_json(Json &json, bool value);
	void to_json(Json &json, int value);
	void to_json(Json &json, double value);
	JsonElement *from_json(const std::string &data);
	static void read_json_object(const std::string &data, int &index, JsonElement &json_object);
	static void read_json_array(const std::string &data, int &index, JsonElement &json_array);
	void from_json(JsonElement &element, const std::string &name, std::string &_value);
	void from_json(JsonElement &element, const std::string &name, bool &_value);
	void from_json(JsonElement &element, const std::string &name, int &_value);
	void from_json(JsonElement &element, const std::string &name, double &_value);
	void free_json(JsonElement *json);

	const std::unordered_map<uint32_t, char> BASE64_TABLE = {
		{0, 'A'},
		{1, 'B'},
		{2, 'C'},
		{3, 'D'},
		{4, 'E'},
		{5, 'F'},
		{6, 'G'},
		{7, 'H'},
		{8, 'I'},
		{9, 'J'},
		{10, 'K'},
		{11, 'L'},
		{12, 'M'},
		{13, 'N'},
		{14, 'O'},
		{15, 'P'},
		{16, 'Q'},
		{17, 'R'},
		{18, 'S'},
		{19, 'T'},
		{20, 'U'},
		{21, 'V'},
		{22, 'W'},
		{23, 'X'},
		{24, 'Y'},
		{25, 'Z'},
		{26, 'a'},
		{27, 'b'},
		{28, 'c'},
		{29, 'd'},
		{30, 'e'},
		{31, 'f'},
		{32, 'g'},
		{33, 'h'},
		{34, 'i'},
		{35, 'j'},
		{36, 'k'},
		{37, 'l'},
		{38, 'm'},
		{39, 'n'},
		{40, 'o'},
		{41, 'p'},
		{42, 'q'},
		{43, 'r'},
		{44, 's'},
		{45, 't'},
		{46, 'u'},
		{47, 'v'},
		{48, 'w'},
		{49, 'x'},
		{50, 'y'},
		{51, 'z'},
		{52, '0'},
		{53, '1'},
		{54, '2'},
		{55, '3'},
		{56, '4'},
		{57, '5'},
		{58, '6'},
		{59, '7'},
		{60, '8'},
		{61, '9'},
		{62, '+'},
		{63, '/'}
	};

	const std::string NEW_LINE = "\r\n";
	const std::string MAGIC_STRING = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
	const int8_t OP_CODE_CLOSE = 0x8;
	const int8_t OP_CODE_TEXT = 0x1;

	TCP_SOCKET listen_socket;
	std::unordered_map<SOCKET_ID, Socket *> sockets;
	SOCKET_ID next_socket_id = 1;
	ServerDesc server_desc;

	bool listen(ServerDesc &desc) {
		server_desc = desc;

		tcp_socket::init();

		// bind
		if (!tcp_socket::bind(server_desc.port, listen_socket)) {
			printf("Failed to bind socket : %s\n", tcp_socket::last_error.c_str());
			tcp_socket::free();
			return false;
		}

		// listen
		if (!tcp_socket::listen(listen_socket)) {
			printf("Failed to listen : %s\n", tcp_socket::last_error.c_str());
			tcp_socket::free();
			return false;
		}

		fd_set read_set;

		while (true) {
			FD_ZERO(&read_set);

			FD_SET(listen_socket, &read_set);

			for (auto kv : sockets) {
				FD_SET(kv.second->socket, &read_set);
			}

			if (!tcp_socket::select(&read_set, nullptr, nullptr)) {
				printf("Failed on select() : %s\n", tcp_socket::last_error.c_str());
				free();
				return false;
			}

			// accept
			if (FD_ISSET(listen_socket, &read_set)) {
				if (!socket_accept(listen_socket)) {
					free();
					return false;
				}
			}

			// receive
			auto it = sockets.begin();

			while (it != sockets.end()) {
				Socket *socket = it->second;

				if (FD_ISSET(socket->socket, &read_set) && !socket_receive(socket)) {
					// disconnect
					SOCKET_ID socket_id = socket->socket_id;

					tcp_socket::close(socket->socket);
					delete socket;
					it = sockets.erase(it);

					if (server_desc.on_disconnect != nullptr) {
						(*server_desc.on_disconnect)(socket_id);
					}
				} else {
					++it;
				}
			}
		}

		free();
	}

	void free() {
		for (auto kv : sockets) {
			tcp_socket::close(kv.second->socket);
			delete kv.second;
		}

		tcp_socket::close(listen_socket);
		tcp_socket::free();
	}

	bool socket_accept(TCP_SOCKET listen_socket) {
		TCP_SOCKET client_socket;

		if (!tcp_socket::accept(listen_socket, client_socket)) {
			printf("Failed to accept socket connection : %s\n", tcp_socket::last_error.c_str());
			tcp_socket::close(listen_socket);
			tcp_socket::free();
			return false;
		}

		SOCKET_ID socket_id = next_socket_id;

		Socket *socket = new Socket;
		socket->socket_id = socket_id;
		socket->socket = client_socket;
		sockets[socket_id] = socket;

		do {	
			if (next_socket_id == 0xffffffff) {
				next_socket_id = 1;
			} else {
				++next_socket_id;
			}
		} while (sockets.find(next_socket_id) != sockets.end());

		return true;
	}

	bool socket_receive(Socket *socket) {
		int num_bytes = tcp_socket::receive(socket->socket, socket->buffer, BUFFER_SIZE);

		if (num_bytes > 0) {
			printf("\nBytes received : %d, socket_id: %d\n", num_bytes, socket->socket_id);

			if (socket->handshake) {
				if (on_socket_data(*socket, num_bytes)) {
					return true;
				}
			} else if (on_socket_handshake(*socket, num_bytes)) {
				socket->handshake = true;

				if (server_desc.on_connect != nullptr) {
					(*server_desc.on_connect)(socket->socket_id);
				}

				return true;
			}
		} else if (num_bytes == 0) {
			printf("Client has closed the connection\n");
		} else {
			printf("Failed to receive client socket data : %s\n", tcp_socket::last_error.c_str());
		}

		return false;
	}

	bool on_socket_handshake(Socket &socket, int num_bytes) {
		int index = 0;

		std::string line;
		read_line_from_buffer(socket, num_bytes, line, index);

		std::string method;
		std::string path;
		std::string version;
		parse_request_line(line, method, path, version);

		std::unordered_map<std::string, std::string> request_headers;

		while (read_line_from_buffer(socket, num_bytes, line, index)) {
			parse_header_line(line, request_headers);
		}

		int status_code;
		std::string status_message;
		std::unordered_map<std::string, std::string> headers;

		if (!has_header_value(request_headers, "Upgrade", "websocket") || !has_header_value(request_headers, "Connection", "Upgrade") || !has_header(request_headers, "Sec-WebSocket-Key")) {
			status_code = 400;
		} else {
			status_code = 101;
			status_message = "Switching Protocols";

			std::string hash = sha1(request_headers["Sec-WebSocket-Key"] + MAGIC_STRING);

			headers["Upgrade"] = "websocket";
			headers["Connection"] = "Upgrade";
			headers["Sec-WebSocket-Accept"] = base64_encode(hash);
		}

		std::string data = "HTTP/1.1 " + std::to_string(status_code) + " " + status_message + NEW_LINE;

		for (auto kv : headers) {
			data += kv.first + ": " + kv.second + NEW_LINE;
		}

		data += NEW_LINE;

		if (!tcp_socket::send(socket.socket, data.c_str(), data.size())) {
			printf("Failed to write response: %s\n", tcp_socket::last_error.c_str());
			return false;
		}

		return true;
	}

	bool read_line_from_buffer(Socket &socket, int num_bytes, std::string &_line, int &_index) {
		bool carriageReturn = false;
		bool found = false;
		int index;

		for (index = _index; index < num_bytes; ++index) {
			if (socket.buffer[index] == '\r') {
				carriageReturn = true;
				continue;
			}

			if (socket.buffer[index] == '\n') {
				if (carriageReturn) {
					found = true;
					break;
				}
			}

			carriageReturn = false;
		}

		if (found) {
			if (index - _index > 1) {
				_line = std::string(socket.buffer + _index, index - _index - 1);
				_index = index + 1;
				return true;
			}

			_index = index + 1;
		}

		return false;
	}

	void parse_request_line(std::string &line, std::string &_method, std::string &_path, std::string &_version) {
		bool first = true;
		int index;

		for (int i = 0; i < line.size(); ++i) {
			if (line[i] == ' ') {
				if (first) {
					_method = line.substr(0, i);
					first = false;
				} else {
					_path = line.substr(index, i - index);		
					_version = line.substr(i + 1);
					return;
				}

				index = i + 1;
			}
		}

		printf("Invalid request line : %s\n", line.c_str());
	}

	void parse_header_line(std::string &line, std::unordered_map<std::string, std::string> &headers) {
		for (int i = 0; i < line.size(); ++i) {
			if (line[i] == ':') {
				headers[line.substr(0, i)] = line.substr(i + 2);
				return;
			}
		}

		printf("Invalid header line : %s\n", line.c_str());
	}

	bool has_header(std::unordered_map<std::string, std::string> &headers, const std::string &name) {
		return headers.find(name) != headers.end();
	}

	bool has_header_value(std::unordered_map<std::string, std::string> &headers, const std::string &name, const std::string &value) {
		auto it = headers.find(name);

		if (it != headers.end()) {
			return it->second == value;
		}

		return false;
	}

	std::string sha1(const std::string &message) {
		uint32_t h[5];
		h[0] = 0x67452301;
		h[1] = 0xefcdab89;
		h[2] = 0x98badcfe;
		h[3] = 0x10325476;
		h[4] = 0xc3d2e1f0;

		uint32_t w[80];

		int index = 0;
		bool padded_one = false;
		bool lastChunk = false;

		while (!lastChunk) {
			for (int i = 0; i < 16; ++i) {
				w[i] = 0;

				for (int j = 0; j < 4; ++j) {
					if (index < message.size()) {
						w[i] |= message[index++] << ((3 - j) * 8);
					} else if (i < 14) {
						if (!padded_one) {
							w[i] |= 1 << (31 - j * 8);
							padded_one = true;
						}

						break;
					} else {
						if (!padded_one) {
							w[i] |= 1 << (31 - j * 8);
							padded_one = true;
						} else if (i == 14) {
							uint64_t message_size = static_cast<uint64_t>(message.size()) * 8;
							w[14] = message_size >> 32;
							w[15] = message_size & 0xffffffff;
							lastChunk = true;
						}

						break;
					}
				}

				if (lastChunk) {
					break;
				}
			}

			for (int i = 16; i < 80; ++i) {
				w[i] = circular_shift_left(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
			}

			uint32_t a = h[0];
			uint32_t b = h[1];
			uint32_t c = h[2];
			uint32_t d = h[3];
			uint32_t e = h[4];

			uint32_t f, k, temp;

			for (int i = 0; i < 80; ++i) {
				if (0 <= i && i <= 19) {
					f = (b & c) | ((~b) & d);
					k = 0x5a827999;
				} else if (20 <= i && i <= 39) {
					f = b ^ c ^ d;
					k = 0x6ed9eba1;
				} else if (40 <= i && i <= 59) {
					f = (b & c) | (b & d) | (c & d);
					k = 0x8f1bbcdc;
				} else {
					f = b ^ c ^ d;
					k = 0xca62c1d6;
				}

				temp = circular_shift_left(a, 5) + f + e + k + w[i];
				e = d;
				d = c;
				c = circular_shift_left(b, 30);
				b = a;
				a = temp;
			}

			h[0] += a;
			h[1] += b;
			h[2] += c;
			h[3] += d;
			h[4] += e;
		}

		std::stringstream ss;
		ss.fill('0');
		ss << std::hex;
		ss << std::setw(8) << h[0];
		ss << std::setw(8) << h[1];
		ss << std::setw(8) << h[2];
		ss << std::setw(8) << h[3];
		ss << std::setw(8) << h[4];

		return ss.str();
	}

	uint32_t circular_shift_left(uint32_t x, int count) {
		return (x << count) | (x >> (32 - count));
	}

	std::string base64_encode(const std::string &data) {
		std::stringstream ss;
		uint32_t value;
		uint32_t buffer = 0;
		int buffer_index = 7;

		std::string encoding;

		for (int i = 0; i < data.size(); i += 2) {
			ss << std::hex << data.substr(i, 2);
			ss >> value;
			ss.clear();

			buffer |= value;

			encoding += BASE64_TABLE.find(buffer >> (buffer_index - 5))->second;

			if (buffer_index == 7) {
				buffer = (buffer & 0x3) << 8;
				buffer_index += 2;
			} else if (buffer_index == 9) {
				buffer = (buffer & 0xf) << 8;
				buffer_index += 2;
			} else {
				encoding += BASE64_TABLE.find(buffer & 0x3f)->second;
				buffer = 0;
				buffer_index = 7;
			}
		}

		if (buffer_index != 7) {
			encoding += BASE64_TABLE.find(buffer >> (buffer_index - 5))->second;
			encoding += (buffer_index == 9) ? "==" : "=";
		}

		return encoding;
	}

	bool on_socket_data(Socket &socket, int num_bytes) {
		uint8_t mask = (socket.buffer[1] & 0x80) >> 7;

		if (mask != 1) {
			printf("Message mask bit is 0, must be 1\n");
			return false;
		}

		uint8_t fin = (socket.buffer[0] & 0x80) >> 7;
		uint8_t op_code = socket.buffer[0] & 0xf;
		uint64_t payload_length = socket.buffer[1] & 0x7f;

		if (op_code == OP_CODE_CLOSE) {
			// close frame
			send_socket_data(socket, OP_CODE_CLOSE);
			return false;
		}

		int buffer_index;

		if (payload_length <= 125) {
			buffer_index = 2;
		} else if (payload_length == 126) {
			payload_length = (static_cast<uint8_t>(socket.buffer[2]) << 8) | static_cast<uint8_t>(socket.buffer[3]);
			buffer_index = 4;
		} else {
			printf("Extended payload not supported\n");
			return false;
		}

		uint8_t masking_key[4];
		masking_key[0] = socket.buffer[buffer_index];
		masking_key[1] = socket.buffer[buffer_index + 1];
		masking_key[2] = socket.buffer[buffer_index + 2];
		masking_key[3] = socket.buffer[buffer_index + 3];
		buffer_index += 4;	

		std::string message;

		for (uint64_t i = 0; i < payload_length; ++i) {
			message += static_cast<char>(socket.buffer[buffer_index + i] ^ masking_key[i % 4]);
		}

		if (server_desc.on_message != nullptr) {
			(*server_desc.on_message)(socket.socket_id, message);
		}

		return true;
	}

	void send(SOCKET_ID socket_id, const std::string &message) {
		auto it = sockets.find(socket_id);

		if (it == sockets.end()) {
			printf("Failed to send socket message: invalid socket id\n");
			return;
		}

		Socket *socket = it->second;

		socket->send_buffer[0] = 0x80 | OP_CODE_TEXT;

		int buffer_index;

		if (message.size() <= 125) {
			socket->send_buffer[1] = static_cast<uint8_t>(message.size());
			buffer_index = 2;
		} else {
			socket->send_buffer[1] = 126;
			socket->send_buffer[2] = message.size() >> 8;
			socket->send_buffer[3] = message.size() & 0xff;
			buffer_index = 4;
		}

		memcpy(&socket->send_buffer[buffer_index], message.c_str(), message.size());

		if (!tcp_socket::send(socket->socket, socket->send_buffer, buffer_index + message.size())) {
			printf("Failed to send socket message: %s\n", tcp_socket::last_error.c_str());
		}
	}

	static void send_socket_data(Socket &socket, uint8_t op_code) {
		socket.send_buffer[0] = 0x80 | op_code;
		socket.send_buffer[1] = 0;

		if (!tcp_socket::send(socket.socket, socket.send_buffer, 2)) {
			printf("Failed to send socket data: %s\n", tcp_socket::last_error.c_str());
		}
	}

	void json_begin(Json &json) {
		json.stream << "{";
	}

	void json_end(Json &json) {
		json.stream << "}";
	}

	template <typename T>
	std::string to_json(T &t) {
		Json json;
		json.first.emplace_back(true);
		to_json(json, t);
		return json.stream.str();
	}

	template <typename T>
	void to_json(Json &json, const std::string &name, T &t) {
		if (json.first.back()) {
			json.first[json.first.size() - 1] = false;
		} else {
			json.stream << ",";
		}

		json.stream << "\"" << name << "\":";
		json.first.emplace_back(true);
		to_json(json, t);
		json.first.pop_back();
	}

	template <typename T>
	void to_json(Json &json, std::vector<T> &value) {
		json.stream << "[";

		for (int i = 0; i < value.size(); ++i) {
			if (i > 0) {
				json.stream << ",";
			}

			json.first.emplace_back(true);
			to_json(json, value[i]);
			json.first.pop_back();
		}
		
		json.stream << "]";
	}

	void to_json(Json &json, const std::string &value) {
		json.stream << "\"" << value << "\"";
	}

	void to_json(Json &json, bool value) {
		json.stream << (value ? "true" : "false");
	}

	void to_json(Json &json, int value) {
		json.stream << value;
	}

	void to_json(Json &json, double value) {
		json.stream << value;
	}

	JsonElement *from_json(const std::string &data) {
		int index = 0;

		if (data[index] == '{') {
			JsonElement *json_object = new JsonElement;
			read_json_object(data, index, *json_object);
			return json_object;
		} else if (data[index] == '[') {
			JsonElement *json_array = new JsonElement;
			read_json_array(data, index, *json_array);
			return json_array;
		} else {
			printf("Invalid JSON data\n");
			return nullptr;
		}
	}

	static void read_json_object(const std::string &data, int &index, JsonElement &json_object) {
		++index;

		while (data[index] != '}') {
			if (data[index] == ',') {
				++index;
			}

			int start_index = ++index;

			while (data[index] != '"') {
				++index;
			}

			std::string name = data.substr(start_index, index - start_index);

			index += 2;

			if (data[index] == '{') {
				JsonElement *jo = new JsonElement;
				json_object.fields[name] = jo;
				read_json_object(data, index, *jo);
				continue;
			} else if (data[index] == '[') {
				JsonElement *ja = new JsonElement;
				json_object.fields[name] = ja;
				read_json_array(data, index, *ja);
				continue;
			}

			bool is_string = data[index] == '"';

			start_index = index++;

			if (is_string) {
				++start_index;
			}

			while ((is_string && data[index] != '"') || (!is_string && data[index] != ',' && data[index] != '}')) {
				++index;
			}

			JsonElement *json_value = new JsonElement;
			json_value->value = data.substr(start_index, index - start_index);
			json_object.fields[name] = json_value;

			if (is_string) {
				++index;
			}
		}

		++index;
	}

	static void read_json_array(const std::string &data, int &index, JsonElement &json_array) {
		++index;

		while (data[index] != ']') {
			if (data[index] == ',') {
				++index;
			}

			if (data[index] == '{') {
				JsonElement *jo = new JsonElement;
				json_array.elements.emplace_back(jo);
				read_json_object(data, index, *jo);
				continue;
			} else if (data[index] == '[') {
				JsonElement *ja = new JsonElement;
				json_array.elements.emplace_back(ja);
				read_json_array(data, index, *ja);
				continue;
			}

			bool is_string = data[index] == '"';

			int start_index = index++;

			if (is_string) {
				++start_index;
			}

			while ((is_string && data[index] != '"') || (!is_string && data[index] != ',' && data[index] != ']')) {
				++index;
			}

			JsonElement *json_value = new JsonElement;
			json_value->value = data.substr(start_index, index - start_index);
			json_array.elements.emplace_back(json_value);

			if (is_string) {
				++index;
			}
		}

		++index;
	}

	void from_json(JsonElement &element, const std::string &name, std::string &_value) {
		auto it = element.fields.find(name);

		if (it != element.fields.end()) {
			_value = it->second->value;
		}
	}

	void from_json(JsonElement &element, const std::string &name, bool &_value) {
		auto it = element.fields.find(name);

		if (it != element.fields.end()) {
			_value = (it->second->value == "true") ? true : false;
		}
	}

	void from_json(JsonElement &element, const std::string &name, int &_value) {
		auto it = element.fields.find(name);

		if (it != element.fields.end()) {
			_value = std::stoi(it->second->value);
		}
	}

	void from_json(JsonElement &element, const std::string &name, double &_value) {
		auto it = element.fields.find(name);

		if (it != element.fields.end()) {
			_value = std::stod(it->second->value);
		}
	}

	template <typename T>
	void from_json(JsonElement &element, const std::string &name, T &_value) {
		auto it = element.fields.find(name);

		if (it != element.fields.end()) {
			from_json(*it->second, _value);
		}
	}

	template <typename T>
	void from_json(JsonElement &element, const std::string &name, std::vector<T> &_values) {
		auto it = element.fields.find(name);

		if (it != element.fields.end()) {
			for (JsonElement *e : it->second->elements) {
				from_json(*e, _values.emplace_back());
			}
		}
	}

	void free_json(JsonElement *json) {
		if (json == nullptr) {
			return;
		}

		for (auto kv : json->fields) {
			free_json(kv.second);
		}

		for (JsonElement *e : json->elements) {
			free_json(e);
		}

		delete json;
	}
}
