#include <sys/types.h>
#include <ifaddrs.h>
#include <stdio.h>
#include <netinet/in.h> 
#include <string.h> 
#include <arpa/inet.h>
#include <netpacket/packet.h>
#include <unistd.h>
#include <linux/if_ether.h>

#define MAPSIZE 100

typedef unsigned long long ull;
typedef unsigned int uint;
typedef unsigned char uchar;

uchar BC[] = "\xFF\xFF\xFF\xFF\xFF\xFF";
int hsz = sizeof(struct ethhdr);

struct IFA{
	char name[100] = {0};
	uint ip, mask, index;
	uchar mac[7];
};

struct Map {
	IFA data[MAPSIZE];
	int cnt = 0;
	IFA& operator[](const char K[])
	{
		for(int i = 0; i < cnt; i++)
			if(strcmp(data[i].name, K) == 0)
				return data[i];
		strcpy(data[cnt].name, K);
		return data[cnt++];
		//return NULL;
	}
	IFA* begin(){
		return data;
	}
	IFA* end(){
		return data + cnt;
	}
};

uint get_ip(struct sockaddr* ifa_addr)
{
	return (uint)((struct sockaddr_in*)ifa_addr)->sin_addr.s_addr;
}

void print_mac(uchar mac[])
{
	for(int i = 0; i < 6; i++)
		printf("%02x%s", mac[i], i == 5 ? "": ":");
}

Map ifa_map;
void fetch_addr()
{
	struct ifaddrs* ifa;
	int family;
	for(getifaddrs(&ifa); ifa; ifa = ifa->ifa_next)
	{
		if(ifa->ifa_addr == NULL)
			continue;
		family = ifa->ifa_addr->sa_family;
		char* name = ifa->ifa_name;
		if(strcmp(name, "lo") == 0)
			continue;
		struct sockaddr_ll *mac = (struct sockaddr_ll*)ifa->ifa_addr;
		uint ip = get_ip(ifa->ifa_addr);
		switch(family)
		{
		case AF_PACKET:
			//printf("AF_PACKET: %s %llx\n", name, *(ull*)(mac->sll_addr)); 
			memcpy(ifa_map[name].mac, mac->sll_addr, 6);
			ifa_map[name].index = mac->sll_ifindex;
			break;
		case AF_INET:
			//printf("AF_INET: %s %x\n", name, ip); 
			ifa_map[name].ip = ntohl(ip);
			ifa_map[name].mask = ntohl(get_ip(ifa->ifa_netmask));
			break;
		}
	}
	for(IFA* it = ifa_map.begin(); it != ifa_map.end(); it++)
	{
		printf("%d - %s\t %x %x ", it->index, it->name, it->ip, it->mask);
		fflush(stdin);
		//write(1, "\0\0\0\0\0\0", 6);
		print_mac(it->mac);
		fflush(stdin);
		puts("");
	}
}

void add_header(char buf[], uchar s[])
{
	struct ethhdr *eth = (struct ethhdr *)buf;
	memcpy(eth->h_source, s, 6);
	for(int i = 0; i < 6; i++)
		printf("%x ", s[i]);
	puts("");
	memcpy(eth->h_dest, BC, 6);
	eth->h_proto = htons(0x0801);
}

void start_recv(int fd)
{
	if(!fork())
	{
		while(1)
		{
			static char buf[1025];
			int c;
			if((c = read(fd, buf, 1024)) > 0)
			{
				struct ethhdr *eth = (struct ethhdr *)buf;
				printf("<");
				print_mac(eth->h_source);
				printf("> ");
				fflush(stdout);
				write(1, buf + hsz, c - hsz);
				fflush(stdout);
			}
		}
	}
}

int main()
{
	fetch_addr();
	int fd = socket(PF_PACKET, SOCK_RAW, htons(0x0801));
	printf("Enter your name: ");
	char username[1025];
	fgets(username, 1024, stdin);
	username[strlen(username) - 1] = 0;
	printf("Welcome, '%s'!\n", username); 
	start_recv(fd);
	struct sockaddr_ll sadr_ll;
	sadr_ll.sll_family = AF_PACKET;
	sadr_ll.sll_halen = ETH_ALEN; 
	sadr_ll.sll_protocol = htons(0x0801);
	memcpy(sadr_ll.sll_addr, BC, 6);
	while(1)
	{
		printf(">>> ");
		static char buf[10250];
		sprintf(buf + hsz, "[%s]: ", username);
		int husz = hsz + strlen(buf + hsz);
		fgets(buf + husz, 10240, stdin);
		int sz = husz + strlen(buf + husz);
		for(IFA* it = ifa_map.begin(); it != ifa_map.end(); ++it)
		{
			printf("send to %d\n", it->index);
			add_header(buf, it->mac);
			sadr_ll.sll_ifindex = it->index; 
			memcpy(sadr_ll.sll_addr, it->mac, 6);
			sendto(fd, buf, sz, 0, (const sockaddr*)&sadr_ll, sizeof(sadr_ll));
		}
		fflush(stdout);
	}
}
