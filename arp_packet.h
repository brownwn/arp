#include<netinet/in.h>
#pragma pack(1)
#define BROADMAC		{0xFF,0xFF,0xFF,0xFF,0xFF,0xFF} //广播MAC
#define EH_TYPE			0x0806							//ARP类型
#define ARP_HRD			0x0001							//硬件类型：以太网接口类型为1		
#define ARP_PRO			0x0800							//协议类型：IP协议类型为0X0800
#define ARP_HLN			0x06							//硬件地址长度：MAC地址长度为6B
#define ARP_PLN			0x04							//协议地址长度：IP地址长度为4B
#define ARP_REQUEST		0x0001							//操作：ARP请求为1
#define ARP_REPLY		0x0002							//操作：ARP应答为2
#define ARP_THA			{0,0,0,0,0,0}					//目的MAC地址：ARP请求中该字段没有意义，设为0；ARP响应中为接收方的MAC地址
#define ARP_PAD			{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0}
#define SPECIAL			0x70707070						//定义获得自己MAC地址的特殊源IP，112.112.112.112

#define ETH_HRD_DEFAULT	{BROADMAC, {0,0,0,0,0,0}, htons(EH_TYPE)}
#define ARP_HRD_DEFAULT	{htons(ARP_HRD), htons(ARP_PRO), ARP_HLN, ARP_PLN, htons(ARP_REQUEST), {0,0,0,0,0,0}, 0, ARP_THA, 0, ARP_PAD}
#define IPTOSBUFFERS 12
typedef struct ethernet_head
{
    unsigned char dest_mac[6];    //destination host mac address
    unsigned char source_mac[6];  //source host mac address
    unsigned short eth_type;      // Ethernet type
}ethernet_head_s;

typedef struct arp_head
{
    unsigned short hardware_type;  //hardware type: Ethernet interface type is 1
    unsigned short protocal_type;  //protocol type:ip is 0X0800
    unsigned char add_len;         //hardware address length:mac address length is 6B
    unsigned char pro_len;         //protocol address length:ip address length is 4B
    unsigned short option;         //operation: arp request is 1, arp reply is 2
    unsigned char sour_addr[6];    //source mac address
    unsigned int sour_ip;         //source ip address
    unsigned char dest_addr[6];    //destination mac address
    unsigned int dest_ip;         //destintion ip address
    unsigned char padding[18];
}arp_head_s;

typedef struct arp_packet
{
    struct ethernet_head eth;
    struct arp_head arp;
}arp_packet_s;
