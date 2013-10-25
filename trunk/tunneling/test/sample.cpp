


#include <iostream>
using namespace std;



#if defined(_WIN32) || defined(_WIN64)
#include <WinSock2.h>
#include <WS2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
#else
#include <netinet/in.h>
#include <unistd.h>
#include <stdlib.h>  
#include <stdio.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <string.h>
#include <errno.h>
#define SOCKET int
#define INVALID_SOCKET  (SOCKET)(~0)
typedef unsigned short      USHORT;
#define SOCKET_ERROR            (-1)
#endif

const unsigned char ICMP_ECHO_REQUEST = 8;
const unsigned char ICMP_ECHO_REPLY = 0;
const unsigned char ICMP_TIMEOUT = 11;

typedef struct _header_icmp_
{
	unsigned char TYPE;
	unsigned char CODE;
	unsigned short CHECKSUM;
	unsigned short ID;
	unsigned short SEQUENCE;
}HEADER_ICMP;

typedef struct _header_ip_
{
	unsigned char header_length:4;
	unsigned char version:4;
	unsigned char tos;
	unsigned short total_length;
	unsigned short identifier;
	unsigned short frag_and_flags;
	unsigned char ttl;
	unsigned char protocol;
	unsigned short checksum;
	unsigned long source_ip;
	unsigned long destination_ip;
}HEADER_IP;

unsigned short checksum(unsigned short* pBuf, int size)
{
	unsigned long cs = 0;
	while(size > 1)
	{
		cs += *pBuf++;
		size -= sizeof(unsigned short);
	}

	if (size)
	{
		cs += *(unsigned char*)pBuf;
	}

	cs = (cs >> 16) + (cs & 0xFFFF);
	cs += (cs >> 16);
	return (unsigned short)(~cs);
}

bool decodeIcmpRsp(char* pBuf, int size, int oSeq)
{
	HEADER_IP* pIpHdr = (HEADER_IP*)pBuf;
	int ipHdrLen = pIpHdr->header_length * 4;
	if (size < (int)(ipHdrLen + sizeof(HEADER_ICMP)))
	{
		return false;
	}

	HEADER_ICMP* pIcmpHdr = (HEADER_ICMP*)(pBuf + ipHdrLen);
	unsigned short id, seq;
	if (ICMP_ECHO_REPLY == pIcmpHdr->TYPE)
	{
		id = pIcmpHdr->ID;
		seq = pIcmpHdr->SEQUENCE;
	}
	else if (ICMP_TIMEOUT == pIcmpHdr->TYPE)
	{
		char* pInnerIpHdr = pBuf + ipHdrLen + sizeof(HEADER_ICMP);
		int innerIpHdrLen = ((HEADER_IP*)pInnerIpHdr)->header_length * 4;
		HEADER_ICMP* pInnerIcmpHdr = (HEADER_ICMP*)(pInnerIpHdr + innerIpHdrLen);
		id = pInnerIcmpHdr->ID;
		seq = pInnerIcmpHdr->SEQUENCE;
	}
	else
		return false;

#if defined(_WIN32) || defined(_WIN64)
	if (id != (unsigned short)GetCurrentProcessId() || ntohs(seq) != oSeq)
#else
	if (id != (unsigned short)getpid() || ntohs(seq) != oSeq)
#endif	
	{
		return false;
	}

	if (ICMP_ECHO_REPLY == pIcmpHdr->TYPE || ICMP_TIMEOUT == pIcmpHdr->TYPE)
	{
		return true;
	}

	return false;
}

//const char* szDst = "115.236.50.10";
const char* szDst = "www.sony.com";

int main()
{
#if defined(_WIN32) || defined(_WIN64)
	WSADATA w = {0};
	WSAStartup(MAKEWORD(2, 2), &w);
#endif

	sockaddr_in dstSockAddr = {0};
	dstSockAddr.sin_family = AF_INET;
	dstSockAddr.sin_addr.s_addr = inet_addr(szDst);
	if (INADDR_NONE == dstSockAddr.sin_addr.s_addr)
	{
		hostent* p = gethostbyname(szDst);
		if (p)
		{
			dstSockAddr.sin_addr.s_addr = (*(in_addr*)p->h_addr).s_addr;
		}
		else
		{
#if defined(_WIN32) || defined(_WIN64)
			WSACleanup();
#endif
			return -1;
		}
	}

	cout << inet_ntoa(dstSockAddr.sin_addr) << endl;

	SOCKET s = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
	if (INVALID_SOCKET == s)
	{
#if defined(_WIN32) || defined(_WIN64)
		WSACleanup();
#endif
		return -1;
	}

	const int DEFAULT_ICMP_DATA_SIZE = 32;
	char szBuf[sizeof(HEADER_ICMP) + DEFAULT_ICMP_DATA_SIZE] = {0};

	HEADER_ICMP* pIcmpHdr = (HEADER_ICMP*)szBuf;
	pIcmpHdr->TYPE = ICMP_ECHO_REQUEST;
	pIcmpHdr->CODE = 0;
#if defined(_WIN32) || defined(_WIN64)
	pIcmpHdr->ID = (USHORT)GetCurrentProcessId();
#else
	pIcmpHdr->ID = (unsigned short)getpid();
#endif	
	
	memset((szBuf + sizeof(HEADER_ICMP)), 'E', DEFAULT_ICMP_DATA_SIZE - 1);


#if defined(_WIN32) || defined(_WIN64)
	int timeout = 30000;
	if (SOCKET_ERROR == setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout)))
	{
		cout << WSAGetLastError() << endl;
#else
	struct timeval timeout={30,0};
	if (SOCKET_ERROR == setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout)))
	{
		char szErrBuf[1024] = {0};
		perror(szErrBuf);
		cout << errno << szErrBuf << endl;
#endif
	}

#if defined(_WIN32) || defined(_WIN64)
	if (SOCKET_ERROR == setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, (char*)&timeout, sizeof(timeout)))
	{
		cout << WSAGetLastError() << endl;
#else
	if (SOCKET_ERROR == setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout)))
	{
		char szErrBuf[1024] = {0};
		perror(szErrBuf);
		cout << errno << szErrBuf << endl;
#endif
	}

	char szRcvBuf[1024] = {0};

	int ttl = 1;
	while(ttl <= 64)
	{
		cout << "Package: " << ttl << endl;
		if (SOCKET_ERROR == setsockopt(s, IPPROTO_IP, IP_TTL, (char*)&ttl, sizeof(ttl)))
		{
#if defined(_WIN32) || defined(_WIN64)
			cout << WSAGetLastError();
			closesocket(s);
			WSACleanup();
#else
			char szErrBuf[1024] = {0};
			perror(szErrBuf);
			cout << errno << szErrBuf << endl;
			close(s);
#endif
			return -1;
		}

		pIcmpHdr->CHECKSUM = 0;
		pIcmpHdr->SEQUENCE = htons(ttl);
		pIcmpHdr->CHECKSUM = checksum((unsigned short*)pIcmpHdr, sizeof(HEADER_ICMP) + DEFAULT_ICMP_DATA_SIZE);

		sendto(s, szBuf, sizeof(szBuf), 0, (sockaddr*)&dstSockAddr, sizeof(dstSockAddr));

		sockaddr_in from;
#if defined(_WIN32) || defined(_WIN64)
		int ifrom = sizeof(sockaddr_in);
#else
		socklen_t ifrom = sizeof(sockaddr_in);
#endif
		while(1)
		{
			int nlen = recvfrom(s, szRcvBuf, 1023, 0, (sockaddr*)&from, &ifrom);
			if (SOCKET_ERROR != nlen)
			{
				if(decodeIcmpRsp(szRcvBuf, nlen, ttl))
				{
					cout << inet_ntoa(from.sin_addr) << endl;
					if (dstSockAddr.sin_addr.s_addr == from.sin_addr.s_addr/*0 == strcmp(inet_ntoa(from.sin_addr), szDst)*/)
					{
#if defined(_WIN32) || defined(_WIN64)
						WSACleanup();
						system("pause");
#endif
						return 0;
					}
				}
				else
				{
					cout << "*" << endl;
				}
				break;
			}
#if defined(_WIN32) || defined(_WIN64)
			else if (WSAETIMEDOUT == WSAGetLastError())
#else
			else if (ETIMEDOUT == errno)
#endif
			{
				cout << "*" << endl;
				break;
			}
			else
			{
#ifdef __linux__
				char szErrBuf[1024] = {0};
				perror(szErrBuf);
				cout << errno << szErrBuf << endl;
				break;
#endif
			}
		}

		++ttl;
	}

#if defined(_WIN32) || defined(_WIN64)
	WSACleanup();
#endif
	system("pause");

	return 0;
}