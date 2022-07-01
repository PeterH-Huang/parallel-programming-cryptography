// server-client.cpp : This contans the main function.

#include <algorithm>
#include <iostream>
#include <WS2tcpip.h>
#include <WinSock2.h>
#include <string>
#include <wsipv6ok.h>
#include <execution>
#include <vector>
#include <ctime>
#include <chrono>
#include "rsa.h"





#pragma comment (lib, "ws2_32.lib")

using namespace std;
using namespace std::chrono;

// global variables
long long* machine2_encrypted_message;
unsigned long machine2_encrypted_message_length;
char* machine1_original_message;
// Create public and private key to attempt to decrypt intercepted password
public_key_class* machine2_public_key;
private_key_class* machine2_private_key;


// Consts shared by helper methods
const long long MIN_PRIME = 10007;
const long long MAX_PRIME = 104729;



// Source => https://www.programiz.com/cpp-programming/examples/prime-number


// Helper function for getting the current time for profiling
auto get_time() { 
	return std::chrono::high_resolution_clock::now(); 
}

long long calculateD(const long long exponent, const long long phi) {

	long long temp_d = phi - 1;

	while (temp_d != 1) {
		// find d = d ≡ e^-1(mod phi)
		long long tempVal = (temp_d * exponent) % phi;
		if (tempVal == 1) {
			return temp_d;
		}
		// decrement the d
		temp_d--;
	}

	// no match found
	return 1;
}

// Check if a number is a prime number
bool isPrimeNumber(const long long num) {

	// if number is 0 or 1 or less it is not a prime number
	if (num <= 1) {
		return false;
	}

	// check from 2 to n-1
	for (long long i = 2; i <= num / 2; i++) {
		if (num % i == 0) {
			return false;
		}
	}

	return true;
}

// Add prime numbers within the range 2 to 2^32 || 2^(sqrt(machine2_modulus)) 
// this is done instead of reading from the file?? maybe try reading from a file
void addPrimeNumbers(std::vector<long long>* v) {

	// Add prime number within the range of min_prime and max_prime to the vector
	for (long long i = MIN_PRIME; i <= MAX_PRIME; i++) {
		// Only Add prime numbers to the vector
		if (isPrimeNumber(i)) {
			v->push_back(i);
		}
	}
}

long long customDecrypter(long long num1){

	// 1. Get the eponent and modulus of the public key 
	long long modulus = machine2_public_key->modulus;
	long long exponent = machine2_public_key->exponent;
	// define the resulting long long or prime or d
	long long d_result;


	// first step check that the number in the range of 2 and the modulus is a prime number
	if ((modulus % num1) != 0) {
		return -1;
	}

	// check for num's corresponsing prime and find its phi
	// getting two prime factors for modulus
	const long long num2 = modulus / num1;
	// given in the slides to find phi => using the prime factors to find phi
	const long long phi = (num1 - 1) * (num2 - 1);

	// with this numbers now available => find d
	d_result = calculateD(exponent, phi);

	//	Log the calculated value of d and the prime number
	cout << "******************************" << std::endl;
	cout << "Selected Prime Number: " << num1 << std::endl;
	cout << "Calculated Value of D: " << d_result << endl;
	cout << "******************************" << std::endl << std::endl;

	// create a private key to attempt to decrypt the encrypted password
	// formula => {d, n} => n is the modulus
	private_key_class private_key{ modulus, d_result };

	// Decrypt the encrypted message 
	char* decrypted_message = rsa_decrypt(machine2_encrypted_message, machine2_encrypted_message_length * 8, &private_key);

	// convert the decrypted message and encrypted message into strings
	if (string(machine1_original_message) != string(decrypted_message)) {
		return -1;
	}
	else {
		machine2_private_key->exponent = private_key.exponent;
		machine2_private_key->modulus = private_key.modulus;

		// Print the message
		cout << "Encrypted Message:\n" << string(decrypted_message) << std::endl << std::endl;

		return d_result;
	}

	
	

}



long long decryptClientMessage() {

	// 1. get the modulus of the public key
	const long long modulus = machine2_public_key->modulus;



	// 2. build a vector => that goes within the range of the upper and lower bound
	// build a vector that takes number within the upper bound and lower bound range
	std::vector<long long> primes_v;
	// fill the vector with prime numbers between the MIN_PRIME AND MAX_PRICE
	addPrimeNumbers(&primes_v);
	// new vectore created that store all eligible prime number that can be used to decrypt the encrypted message
	std::vector<long long> prime_numbers(primes_v.size());

	// Reference: Parallel_Sort => from tutorial 2 code
	// 1. get the starting time
	auto start = get_time();

	// begins parallel execution => looking for possible number that or prime that would decrypt the encrypted message
	std::transform(std::execution::par,primes_v.begin(), primes_v.end(), prime_numbers.begin(), customDecrypter);

	// 3. set stop time
	auto finish = get_time();

	// 4. extract the total time to finish the execution
	auto total_duration = duration_cast<microseconds>(finish - start);

	// Print execution time to the console
	std::cout << endl;
	std::cout << "The total time of execution (4 processors) => " << total_duration.count() << " microseconds." << std::endl << std::endl;


	// finally, getting d
	std::vector<long long>::iterator result = std::find_if(prime_numbers.begin(), prime_numbers.end(), [](long long i) { return i != -1; });

	//return the result
	return *result;
}


void main(){

	// Create header for current machine 
	cout << "=======================================================================" << endl;
	cout << "Machine 2 => Machine shares the created public key in machine 3 with machine 1" << endl;
	cout << "Machine 2 forwards encrypted message from machine 1 => machine 3" << endl;
	cout << "Machine 2 decrypts the message sent to machine 3 by assuming a private key" << endl;
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


	



	// PART A - Creating server for machine 2 => recieve client message from Machine 1
	
	// 1. Setting up the server to receive incoming message from machine 1
	// Create a socket
	SOCKET listening = socket(AF_INET, SOCK_STREAM, 0);
	if (listening == INVALID_SOCKET)
	{
		cerr << "Can't create a socket! Quitting" << endl;
		return;
	}

	// Bind the ip address and port to a socket
	sockaddr_in machine2_server_hint;
	machine2_server_hint.sin_family = AF_INET;
	machine2_server_hint.sin_port = htons(54000);
	machine2_server_hint.sin_addr.S_un.S_addr = INADDR_ANY; // Could also use inet_pton .... 

	bind(listening, (sockaddr*)&machine2_server_hint, sizeof(machine2_server_hint));

	// Tell Winsock the socket is for listening 
	listen(listening, SOMAXCONN);

	// Wait for a connection
	sockaddr_in client;
	int clientSize = sizeof(client);

	SOCKET machine1_clientSocket = accept(listening, (sockaddr*)&client, &clientSize);

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

	

	// Starting the server 
	int startServer;
	cout << "Machine2> ";
	cin >> startServer;
	cout << endl;

	// Create buffer to recieve messages send by machine1 client
	char buf_machine2_server[4096];

	



	// PART B - Create client for machine 2 
	// => sends the message received through the server socket from machine 1 to send to machine 2 which goes to machine 3 
	// => the server that has the private key to decrypt the message

	string ipAddress = "127.0.0.1";			// IP Address of the server
	int port = 54000;						// Listening port # on the server

	// Create socket
	SOCKET machine2_client_sock = socket(AF_INET, SOCK_STREAM, 0);
	if (machine2_client_sock == INVALID_SOCKET)
	{
		cerr << "Can't create socket, Err #" << WSAGetLastError() << endl;
		WSACleanup();
		return;
	}

	// Fill in a hint structure
	sockaddr_in machine2_client_hint;
	machine2_client_hint.sin_family = AF_INET;
	machine2_client_hint.sin_port = htons(port);
	inet_pton(AF_INET, ipAddress.c_str(), &machine2_client_hint.sin_addr);

	// Connect to server
	int connResult = connect(machine2_client_sock, (sockaddr*)&machine2_client_hint, sizeof(machine2_client_hint));


	if (connResult == SOCKET_ERROR)
	{
		cerr << "Can't connect to server, Err #" << WSAGetLastError() << endl;
		closesocket(machine2_client_sock);
		WSACleanup();
		return;
	}

	// 2. Display the currently connected machine
	cout << "Current Connection: Machine 3 and Machine 2  client connected." << endl;
	cout << "The encrypted message from machine 1 is sent from => Machine 2 => to Machine 3" << endl;
	cout << endl;

	// Do-while loop to send and receive data
	char buf_machine2_client[4096];
	std::string userInput;

	// Steps to communciate between machine2_client and machine3_server
	// Reference : Same approach used to parse the public key in machine 1
	// Receiving the public key when connected to the server => machine3_server

	// 1. Recieve the public key
	int bytesRecieved = recv(machine2_client_sock, buf_machine2_client, 4096, 0);
	// 2. Create a public and private key to store the recieved public key
	struct public_key_class pub[1];
	struct private_key_class priv[1];


	// 3. extracting the public key
	string client_public_key = string(buf_machine2_client, 0, bytesRecieved);
	size_t client_public_key_length = client_public_key.length();

	// 4. Parse the public key => extracting the public modulus and exponent
	string separator = "-";
	size_t separatorIndex = client_public_key.find(separator);
	string client_public_key_mod = client_public_key.substr(0, separatorIndex);
	string client_public_key_exp = client_public_key.substr(separatorIndex + 1, client_public_key_length);

	// 5. Convert the extracted public key to long long
	// source => http://www.cplusplus.com/reference/string/stoll/
	const long long pubModulus = std::stoll(client_public_key_mod);
	const long long pubExponent = std::stoll(client_public_key_exp);

	// 6. Populate the client public_key_class with the public key recieved from the server => Machine3_server
	pub->modulus = pubModulus;
	pub->exponent = pubExponent;

	// 7. update the global public and private keys
	machine2_public_key = pub;
	machine2_private_key = priv;

	// DEBUG: Print the public key to the client 
	cout << "Public Key:\nModulus: " << (long long)pub->modulus << " Exponent: " << (long long)pub->exponent << std::endl;


	// 7. Send the public key received from machine3 and send to machine1 from machine2_server port
	ZeroMemory(buf_machine2_server, 4096);
	strcpy_s(buf_machine2_server, client_public_key.c_str());
	send(machine1_clientSocket, buf_machine2_server, client_public_key.length() + 1, 0);


	// PART C - Managing communciation between machine 1 and machine 3
	// This also attempts to decrpyt the intercept the message sent from machine 1 to machine 3


	while (true)
	{
		ZeroMemory(buf_machine2_server, 4096);

		// PART A - Receiving the message sent from machine 1
		// Wait for client to send data => machine1 client sending to machine3
		int bytesReceived = recv(machine1_clientSocket, buf_machine2_server, 4096, 0);
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

		// 2. Receive the original message to be sent to the client
		string originalMessage = string(buf_machine2_server, 0, bytesReceived);
		int originalMessage_length = originalMessage.length();

		// 3. TODO: Set the original message to the global variable to compare the decrypted message
		// cast the original message to const char *
		machine1_original_message = const_cast<char *>(originalMessage.c_str());
		
	

		// PART B: Send confirmation prompt for machine1 to send the encrypted message 
		string confirmReceieveMsg = "Machine2 Confirmation => Received Real User Input from Machine 1";
		strcpy_s(buf_machine2_server, confirmReceieveMsg.c_str());
		send(machine1_clientSocket, buf_machine2_server, confirmReceieveMsg.length() + 1, 0);


		// PART C: Receive the encrypted messaged from machine1 => to be sent to machine3
		ZeroMemory(buf_machine2_server, 4096);
		int bytesReceived_encrypted = recv(machine1_clientSocket, buf_machine2_server, 4096, 0);
		if (bytesReceived_encrypted == SOCKET_ERROR)
		{
			cerr << "Error in recv(). Quitting" << endl;
			break;
		}

		// edge: if there is a disconnection break out the loop
		if (bytesReceived_encrypted == 0)
		{
			cout << "Client disconnected " << endl;
			break;
		}


		// 1. store the intercepted message from machine 1
		string encryptedMessage = string(buf_machine2_server, 0, bytesReceived_encrypted);
		int encryptedMessage_length = encryptedMessage.length();
		// update the machine2_encrypted message length
		machine2_encrypted_message_length = originalMessage_length + 1;

		// 3. Allocate memory to store the encrypted message 
		machine2_encrypted_message = (long long*)malloc((machine2_encrypted_message_length) * sizeof(long long));
		string copyEncryptedMessage = encryptedMessage;


		// 4. Format the encrypted message => go through the array and add them to encrypted array
		string separator = " ";
		for(int i=0; i < machine2_encrypted_message_length; i++){
			if (i == originalMessage_length) {
				
				machine2_encrypted_message[i] = std::stoll(copyEncryptedMessage);
			}
			else {
				int index = copyEncryptedMessage.find(separator);
				// Logic: Find the long long before " " and store that in the long long * array for encrypted message
				string tempValue = copyEncryptedMessage.substr(0, index);

				// add the value to the array 
				machine2_encrypted_message[i] = std::stoll(tempValue);

				// update the start index
				int newStartIndex = index + 1;
				// get a new end index
				int newEndIndex = encryptedMessage_length - newStartIndex;

				// update the copy string
				copyEncryptedMessage = copyEncryptedMessage.substr(newStartIndex, newEndIndex);

				
			}
		}


		// Compare the original message and the decrypted message

		cout << "=======================================================================" << endl;
		cout << "Machine 2 Information" << endl;
		cout << "The unecrypted message sent by machine 1 for verification:\n" << machine1_original_message << endl;
		cout << endl << endl;
		cout << "Encrypted Message Intercepted message:\n" << endl;

		for (int i = 0; i < originalMessage_length; i++) {

			cout << machine2_encrypted_message[i] << " ";
		}
		cout << endl << endl;

		



		// PART C: Decrypt the message intercepted from machine 1
		// Encrypted the original message sent and attempt to decrypted the message 
		cout << "Decrypted Intercepted Message from machine 1:\n" << endl;
		long long result = decryptClientMessage();
		string result_str = to_string(result);
		
		cout << "=======================================================================" << endl;




		// PART D - Send the encrypted message recieved from machine 1 to machine3
		int sendEncryptedResult = send(machine2_client_sock, encryptedMessage.c_str(), encryptedMessage.size() + 1, 0);
		if (sendEncryptedResult != SOCKET_ERROR)
		{
			// Wait for response
			ZeroMemory(buf_machine2_client, 4096);
			int bytesReceived = recv(machine2_client_sock, buf_machine2_client, 4096, 0);
			if (bytesReceived > 0)
			{
				
				string confirmation_msg = string(buf_machine2_client, 0, bytesReceived);

				// 1. Display the confirmation message for message delivered frm machine2_client to machine3
				cout << "Machine2> " << confirmation_msg << endl;

				// 2. Send a confirmation to machine 1 that machine3 has recieved the encrypted message
				string confirmation_msg_machine1 = "Machine2 Confirmation => Message Sent to machine 3";
				ZeroMemory(buf_machine2_server, 4096);
				strcpy_s(buf_machine2_server, confirmation_msg_machine1.c_str());
				send(machine1_clientSocket, buf_machine2_server, confirmation_msg_machine1.length() + 1, 0);
				
			}
		}

	}
	

	
	


	// close the socket
	closesocket(machine1_clientSocket);
	// Cleanup winsock
	WSACleanup();
	
	system("pause");
}
