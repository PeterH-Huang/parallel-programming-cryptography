// server.cpp : This file contains the 'main' function. Program execution begins and ends there.
#include <iostream>
#include <WS2tcpip.h>
#include <string>
#include "rsa.h"
#include <sstream>
#include <vector>
#include <ctime>
#include <chrono>

#pragma comment (lib, "ws2_32.lib")

using namespace std;
using namespace std::chrono;

// Helper function for getting the current time for profiling
auto get_time() {
	return std::chrono::high_resolution_clock::now();
}

void main()
{
	// Create header for current machine 
	cout << "=======================================================================" << endl;
	cout << "Machine 3 => Machine that creates the public shared with machine 2 and 1" << endl;
	cout << "Only Machine 3 knows the private key for decrypting encrypted messaged" << endl;
	cout << "=======================================================================" << endl;

	cout << endl;


	// Initialze winsock
	WSADATA wsData;
	WORD ver = MAKEWORD(2, 2);

	int wsOk = WSAStartup(ver, &wsData);
	if (wsOk != 0)
	{
		cerr << "Can't Initialize winsock! Quitting" << endl;
		return;
	}

	// Create a socket
	SOCKET listening = socket(AF_INET, SOCK_STREAM, 0);
	if (listening == INVALID_SOCKET)
	{
		cerr << "Can't create a socket! Quitting" << endl;
		return;
	}

	// Bind the ip address and port to a socket
	sockaddr_in hint;
	hint.sin_family = AF_INET;
	hint.sin_port = htons(54000);
	hint.sin_addr.S_un.S_addr = INADDR_ANY; // Could also use inet_pton .... 

	bind(listening, (sockaddr*)&hint, sizeof(hint));

	

	// Tell Winsock the socket is for listening 
	listen(listening, SOMAXCONN);

	// Wait for a connection
	sockaddr_in client;
	int clientSize = sizeof(client);

	SOCKET clientSocket = accept(listening, (sockaddr*)&client, &clientSize);

	char host[NI_MAXHOST];		// Client's remote name
	char service[NI_MAXSERV];	// Service (i.e. port) the client is connect on

	ZeroMemory(host, NI_MAXHOST); // same as memset(host, 0, NI_MAXHOST);
	ZeroMemory(service, NI_MAXSERV);

	if (getnameinfo((sockaddr*)&client, sizeof(client), host, NI_MAXHOST, service, NI_MAXSERV, 0) == 0)
	{
		cout << host << " connected on port " << service << endl;
	}
	else
	{
		inet_ntop(AF_INET, &client.sin_addr, host, NI_MAXHOST);
		cout << host << " connected on port " <<
			ntohs(client.sin_port) << endl;
	}

	// Close listening socket
	closesocket(listening);

	

	// While loop: accept and echo message back to client
	char buf[4096];
	// NOTE: 
	ZeroMemory(buf, 4096);
	// Machine 3 sends the public key to the client => Machine 1 so encrypted messages can be sent 

	// 1. Create a private and public key 
	struct public_key_class pub[1];
	struct private_key_class priv[1];

	// 2. Generate the public and private encryption keys using rsa_gen function 
	rsa_gen_keys(pub, priv, PRIME_SOURCE_FILE);

	// Debug :: Print the private and public key to the console
	cout << "Private Key:\nModulus: " << (long long)priv->modulus << " Exponent: " << (long long)priv->exponent << std::endl;
	cout << "Public Key:\nModulus: " << (long long)pub->modulus << " Exponent: " << (long long)pub->exponent << std::endl;

	// 3. Convert the modulus and exponent to string and send the concatentated string to the client side
	string pubModulus = std::to_string(pub->modulus);
	string pubExponent = std::to_string(pub->exponent);
	string public_key = pubModulus + "-" + pubExponent;

	// 4. copy the public key which is converted to char *  into the buffer 
	strcpy_s(buf, public_key.c_str());
	
	// 5. Send encrypting key to the connected client => in this case the public key
	send(clientSocket, buf, public_key.size() + 1, 0);

	while (true)
	{
		ZeroMemory(buf, 4096);

		// Wait for client to send data
		int bytesReceived = recv(clientSocket, buf, 4096, 0);
		if (bytesReceived == SOCKET_ERROR)
		{
			cerr << "Error in recv(). Quitting" << endl;
			break;
		}

		if (bytesReceived == 0)
		{
			cout << "Client disconnected " << endl;
			break;
		}

		

		// PART A - Steps to decrypt a received message
		// 1. recieve the encrypted message 
		string message = string(buf, 0, bytesReceived);

		cout << endl;
		cout << "========================================================" << endl;
		cout << "Encrypted message from machine 1: \n" << message << endl;

		// Resource => https://stackoverflow.com/questions/947621/how-do-i-convert-a-long-to-a-string-in-c
		// 2. parsed the bytes or long long sent from the client to the server
		std::stringstream messageReceived(message);
		
		// 3. create iterators => for the begin and end of "messageReceived"
		std::istream_iterator<std::string> begin(messageReceived);
		std::istream_iterator<std::string> end;

		// create a vector to store the message received
		std::vector<std::string> vectorMessage(begin, end);

		// 4. Convert the message received from string to long long *
		int messageReceived_length = vectorMessage.size();
		 
		// create a long long * and allocate memory size for the length of message recieved from the client 
		long long* encryptedMessage = (long long*)malloc(messageReceived_length * sizeof(long long));

		// 5. use a for-loop to change each string to its respective long
		for (int i = 0; i < messageReceived_length; i++) {

			encryptedMessage[i] = std::stoll(vectorMessage[i]);
		}
		auto start = get_time();
		// 6. decrypt the message sent from the client using private key
		string decryptedMessage = rsa_decrypt(encryptedMessage, messageReceived_length * 8, priv);
		auto finish = get_time();
		auto total_duration = duration_cast<microseconds>(finish - start);
		// 7. print out the decrypted message
		cout << "Decrypted message from machine 1:\n" << decryptedMessage << endl;
		cout << endl;
		cout << "Decryption time (4 processors) => " << total_duration.count() << " microseconds." << endl;
		cout << "========================================================" << endl;
		cout << endl;


		// PART B - Send confirmation for the message reeieved	
		ZeroMemory(buf, 4096);
		// 1. Create confirmation messsage
		string confirmationMessage = "Machine3 Confirmation => Message Received from machine 2";
		// 2. copy the message to the buffer
		// strcpy_s(buf, confirmationMessage.c_str());
		strcpy_s(buf, confirmationMessage.c_str());
		// Echo message back to client => Confirmation for message recieved from the client 
		//send(clientSocket, buf, bytesReceived + 1, 0);
		send(clientSocket, buf, confirmationMessage.length() + 1, 0);

	}

	// Close the socket
	closesocket(clientSocket);

	// Cleanup winsock
	WSACleanup();

	system("pause");
}
