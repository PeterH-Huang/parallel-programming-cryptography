// client.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include <string>
#include <WS2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
#include "rsa.h"
#include <sstream>

using namespace std;
// source => http://www.cplusplus.com/reference/string/stoll/
void main()
{
	// Create header for current machine 
	cout << "=======================================================================" << endl;
	cout << "Machine 1 => shares the encrypted message with machine 3 through machine 2" << endl;
	cout << "Machine 1 also send the unencrypted user input to machine 2 to compare with its decrypted message" << endl;
	cout << "=======================================================================" << endl;
	cout << endl;

	string ipAddress = "127.0.0.1";			// IP Address of the server
	int port = 54000;						// Listening port # on the server

	// Initialize WinSock
	WSAData data;
	WORD ver = MAKEWORD(2, 2);
	int wsResult = WSAStartup(ver, &data);
	if (wsResult != 0)
	{
		cerr << "Can't start Winsock, Err #" << wsResult << endl;
		return;
	}

	// Create socket
	SOCKET sock = socket(AF_INET, SOCK_STREAM, 0);
	if (sock == INVALID_SOCKET)
	{
		cerr << "Can't create socket, Err #" << WSAGetLastError() << endl;
		WSACleanup();
		return;
	}

	// Fill in a hint structure
	sockaddr_in hint;
	hint.sin_family = AF_INET;
	hint.sin_port = htons(port);
	inet_pton(AF_INET, ipAddress.c_str(), &hint.sin_addr);

	// Connect to server
	int connResult = connect(sock, (sockaddr*)&hint, sizeof(hint));


	if (connResult == SOCKET_ERROR)
	{
		cerr << "Can't connect to server, Err #" << WSAGetLastError() << endl;
		closesocket(sock);
		WSACleanup();
		return;
	}

	// Do-while loop to send and receive data
	char buf[4096];
	std::string userInput; 


	// Receiving the public key when connect to the server
	ZeroMemory(buf, 4096);

	
	// 1. Create a public and private key to store the recieved public key
	struct public_key_class pub[1];
	struct private_key_class priv[1];

	// 2. Recieve the public key
	int bytesRecieved = recv(sock, buf, 4096, 0);

	// 3. extracting the public key
	string client_public_key = string(buf, 0, bytesRecieved);
	size_t client_public_key_length = client_public_key.length();

	// 4. Parse the public key => extracting the public modulus and exponent
	string separator = "-";
	size_t separatorIndex = client_public_key.find(separator);
	string client_public_key_mod = client_public_key.substr(0, separatorIndex);
	string client_public_key_exp = client_public_key.substr(separatorIndex + 1, client_public_key_length);

	// 5. Convert the extracted public key to long long
	const long long pubModulus = std::stoll(client_public_key_mod);
	const long long pubExponent = std::stoll(client_public_key_exp);

	// 6. Populate the client public_key_class with the public key recieved from the server => Machine 3
	pub->modulus = pubModulus;
	pub->exponent = pubExponent;

	// DEBUG: Print the public key to the client 
	cout << "Public Key:\nModulus: " << (long long)pub->modulus << " Exponent: " << (long long)pub->exponent << std::endl;

	

	do
	{
		// Prompt the user for some text
		cout << "Enter message to send to Machine 3> ";
		getline(cin, userInput);

		if (userInput.size() > 0)		// Make sure the user has typed in something
		{
			
			// 1. encrypt the user input 
			long long* encryptedUserInput = rsa_encrypt(userInput.c_str(), userInput.size() + 1, pub);

			// PART 1 -  Send the user input to machine2_client
			// Send the user Input
			int sendUserInputResult = send(sock, userInput.c_str(), userInput.size() + 1, 0);
			if (sendUserInputResult != SOCKET_ERROR)
			{
				// Wait for response
				ZeroMemory(buf, 4096);
				int bytesReceived = recv(sock, buf, 4096, 0);
				if (bytesReceived > 0)
				{
					string messageConfirm = string(buf, 0, 4096);
					// check for a confirmation message before the encrypted message is sent to machine2_client
					if (messageConfirm != "Machine2 Confirmation => Received Real User Input from Machine 1") {
						break;
					}
					// Echo response to console
					cout << "Machine1> " << messageConfirm << endl;

				}
			}
			
			// 2. parse the encrypted user input
			string encryptedMessage = "";
			for (int i = 0; i < userInput.size() + 1; i++) {

				if (i == userInput.size()) {
					// exclude the space separator
					encryptedMessage += to_string(encryptedUserInput[i]);
				}
				else {
					
					// print each long with a  space separator
					encryptedMessage += to_string(encryptedUserInput[i]) + " ";
				}
				
			}
		
			// PART 2 - Send the encrypted message to the machine2_client => which gets forwarded to machine3
			// Send encrypted user input
			int sendEncryptedResult = send(sock, encryptedMessage.c_str(), encryptedMessage.size() + 1, 0);
			if (sendEncryptedResult != SOCKET_ERROR)
			{
				// Wait for response
				ZeroMemory(buf, 4096);
				int bytesReceived = recv(sock, buf, 4096, 0);
				if (bytesReceived > 0)
				{
					// Echo response to console
					cout << "SERVER 2> " << string(buf, 0, bytesReceived) << endl;
				}
			}
		}

	} while (userInput.size() > 0);

	// Gracefully close down everything
	closesocket(sock);
	WSACleanup();
}
