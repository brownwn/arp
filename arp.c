#include <stdio.h>
#include <stdlib.h>
#include "arp_packet.h"
#include <pcap/pcap.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <sys/time.h>
pthread_t ntid;
typedef struct dev_ip
{
    char dev[10];
    unsigned long ip;
    unsigned long nmask;
}dev_ip_s;

typedef struct send_par
{
    char* devname;
    unsigned char* macaddr;
    unsigned long localip;
    unsigned long mask;
    long stime;
}send_par_s;
void printids(const char *s)
{
    pid_t      pid;
    pthread_t  tid;
    pid = getpid();
    tid = pthread_self();
    printf("%s pid %u tid %u (0x%x)\n", s, (unsigned int)pid, (unsigned int)tid, (unsigned int)tid);
}

void * thr_fn(void *arg)
{
    printids("new thread: \n");
    return((void * )0);
}

char* IpToStr(unsigned long ulIP)	
{							
	static char output[IPTOSBUFFERS][3 * 4 + 3 + 1];
	static short which;									
	unsigned char* chIP;
	chIP = (unsigned char*)&ulIP;							
	which = (which + 1 == IPTOSBUFFERS ? 0 : which + 1); 
	sprintf(output[which], "%d.%d.%d.%d", chIP[0], chIP[1], chIP[2], chIP[3]); 
	return output[which];
}

char* MacToStr(unsigned char* chMAC)
{							
	static unsigned char uMac[18];
        int i;
	for(i=0; i < 17; i++)
	{
		if ((i+1) % 3)
		{
			if (!(i % 3))
			{
				if ((chMAC[i/3] >> 4) < 0x0A)
				{
					uMac[i] = (chMAC[i/3] >> 4) + 48;
				}
				else
				{
					uMac[i] = (chMAC[i/3] >> 4) + 55;
				}
				if ((chMAC[i/3] & 0x0F) < 0x0A)
				{
					uMac[i+1] = (chMAC[i/3] & 0x0F) + 48;
				}
				else
				{
					uMac[i+1] = (chMAC[i/3] & 0x0F) + 55;
				}
			}
		}
		else
		{
			uMac[i] = '-';
		}
	}
	uMac[17] = '\0';
	return (char*)uMac;
}

void * thr_rev(void *arg)
{
        struct send_par* p=(struct send_par*)arg;
        printf("in thr_rev:%s\n",p->devname);        
        
        pcap_t* pAdaptHandle;   //打开网卡适配器时用
        char errbuf[PCAP_ERRBUF_SIZE + 1];
        if((pAdaptHandle = pcap_open_live(p->devname, 256, 0, 100, errbuf)) == NULL)
        {
            printf("cant't open dev\n");
        }
        //string ipWithMac;
        char* filter = "ether proto\\arp";
        struct bpf_program fcode;
        int res;
        unsigned short arp_op = 0;
        unsigned char arp_sha [6];
        unsigned long arp_spa = 0;
        unsigned long arp_tpa = 0;
        struct pcap_pkthdr *header;
        const u_char *pkt_data;
        if (pcap_compile(pAdaptHandle, &fcode, filter, 1, (unsigned long)(0xFFFF0000)) < 0)
        {
            printf("filter error!\n");
        }
        //set the filter
        if (pcap_setfilter(pAdaptHandle, &fcode) < 0)
        {
            printf("filter adapter error!\n");
        }
        printf("*******************************\n");
        while(1)
        {
                int i = 0;
                //ipWithMac = "";
                res = pcap_next_ex(pAdaptHandle, &header, &pkt_data);
                //printf("recieve:%d\n",res);
                if (!res)
                {
                        continue;
                }
                memcpy(&arp_op, pkt_data + 20, 2);
                memcpy(arp_sha, pkt_data + 22, 6);
                memcpy(&arp_spa, pkt_data + 28, 4);
                memcpy(&arp_tpa,pkt_data+38,4);
                if(arp_op == htons(ARP_REPLY) && arp_tpa==p->localip)
                {
                    struct timeval etv;
    		    gettimeofday(&etv,NULL);
                    long end = ((long)etv.tv_sec)*1000+(long)etv.tv_usec/1000;
                    long diff = end-p->stime;
                    printf("ip:%s,mac:%s,arptime:%ldms\n",IpToStr(arp_spa),MacToStr(arp_sha),diff);
                }
        }
        return((void * )0);
}


struct dev_ip  getDeviceIp(){
    /*
    struct pcap_if_t{
        pcap_if_t *next;
        char *name;
        char *description;
        pcap_addr *addresses;
        U_int falgs;
    };
    struct pcap_addr_t{
        next;
        addr;
        netmask;
        broadaddr;
        dstaddr;
    }
    */
    struct dev_ip di;
    pcap_if_t *alldevs;
    pcap_if_t *d;
    int i=0,nDev=0,getin;
    pcap_addr_t* pAdr;
    unsigned long chLocalIp;
    char errbuf[PCAP_ERRBUF_SIZE];
    char *ip_str="";
    /* Retrieve the device list */
    if (pcap_findalldevs(&alldevs, errbuf) == -1)//返回网卡列表，alldevs指向表头
    {
        fprintf(stderr,"Error in pcap_findalldevs: %s\n", errbuf);
        exit(1);
    }
    /* Print the list */
    for(d=alldevs;d;d=d->next)
    {
        printf("%d. %s", ++nDev, d->name);
        if (d->description)
        printf(" (%s)\n", d->description);
        else printf(" (No description available)\n");
    }
    puts("Please choose a interface to use:");
    scanf("%d",&getin);
    if(getin < 1 || getin > nDev )
    {
        puts("Please choose a correct interface.\n");
    }else{
        printf("You choosen interface:%d\n",getin);
        for (d=alldevs,i=0;i<getin-1;d=d->next,i++);
        pAdr = d->addresses;
        char* name = d->name;
        while(pAdr)
        {   
             chLocalIp = ((struct sockaddr_in *)pAdr->addr)->sin_addr.s_addr;
             if(chLocalIp < 10)
             {
                 pAdr = pAdr->next;
                 continue;
             }
             ip_str = IpToStr(chLocalIp);
             printf("%s\n",ip_str);
             di.ip = chLocalIp;
             di.nmask = ((struct sockaddr_in *)pAdr->netmask)->sin_addr.s_addr;
             memcpy(di.dev,name,sizeof(name));
             pcap_freealldevs(alldevs);
             return di;
             //pAdr = pAdr->next;
        }
    }
    if(strlen(ip_str)<2)
    {
       printf("\nNo interfaces found! Make sure the interface has a available ip.\n");
       return di;
    }
    /* We don't need any more the device list. Free it */
    //pcap_freealldevs(alldevs);
    //return chLocalIp;

}
//char* 
//void getDev(char* dev,char* errbuf)

unsigned char* enArpReqPack(unsigned char* source_mac, unsigned char* arp_sha, unsigned long chLocalIP, unsigned long arp_tpa, int PackSize)
{	//封装ARP请求包
        printf("In enArpReqPack:%s\n",source_mac);
        printf("sentd to %s\n",IpToStr(arp_tpa));
	static arp_packet_s arpPackStru;
	arp_packet_s arpDefaultPack= {ETH_HRD_DEFAULT,ARP_HRD_DEFAULT};
        memcpy(&arpPackStru,&arpDefaultPack,sizeof(arpDefaultPack));        

        //memset(arpPackStru.eth.dest_mac,0xFF,6);
        printf("In enArpReqPack:%s\n",source_mac);
	memcpy(arpPackStru.eth.source_mac,source_mac,6);
        //arpPackStru.eth.eth_type = htons(EH_TYPE);

        //arpPackStru.arp.hardware_type = htons(ARP_HRD);
        //arpPackStru.arp.protocal_type = htons(ARP_PRO);
        //arpPackStru.arp.add_len = ARP_HLN;
        //arpPackStru.arp.pro_len = ARP_PLN;
        //arpPackStru.arp.option = htons(ARP_REQUEST);
	memcpy(arpPackStru.arp.sour_addr,arp_sha,6);
	arpPackStru.arp.sour_ip=(unsigned int)chLocalIP;
        memset(arpPackStru.arp.dest_addr,0,6);	
	arpPackStru.arp.dest_ip=(unsigned int)arp_tpa;
        //memset(arpPackStru.arp.padding,0,18);
	return (unsigned char *)&arpPackStru;
}

void sendArpPack(char* pDevName, unsigned char* mac, unsigned long chLocalIP, unsigned long netmask)
{  
   printf("In sendArpPack mac is %s\n:",mac);
   pcap_t* pAdaptHandle;
   char errbuf[PCAP_ERRBUF_SIZE+1];
   if((pAdaptHandle=pcap_open_live(pDevName, 256, 1, 100, errbuf)) == NULL)
   {
      printf("can not open adapter!\n");
   }
   struct pcap_pkthdr *header;
   const u_char *pkt_data;
   int res,gotMac=0;
   unsigned short arp_op;
   static unsigned char arp_sha[6];
   unsigned long arp_spa=0;
   unsigned long arp_tpa=0;
   //unsigned long send_tpa=ntohl(2181146817);
   unsigned char source_mac[6]={0,0,0,0,0,0};
   unsigned char *arp_packet_for_self;
   unsigned long destIP=ntohl(2197924032);
   printf("sendto:%s\n",IpToStr(2013374656));
   destIP=2013374656;
   printf("before sendArpPack mac is %s\n:",mac);
   
   arp_packet_for_self=enArpReqPack(mac, mac, chLocalIP, destIP, 60);
   int netsize=0;
   //unsigned long nlNetMask=0;
   netsize=~ntohl(netmask);
   arp_tpa=ntohl(chLocalIP&netmask);
   int i;
   for(i=0; i<netsize; i++){
       arp_tpa++;
       unsigned long send_tpa=htonl(arp_tpa);
       memcpy(arp_packet_for_self+38,&send_tpa,4);
       pcap_sendpacket(pAdaptHandle, arp_packet_for_self, 60);
       //sleep(1);
   }
   pcap_close(pAdaptHandle);
}



unsigned char* GetSelfMac2(char* pDev,unsigned char* mac)
{
    struct ifreq ifreq;
    int sock = 0;
    
    sock = socket(AF_INET,SOCK_STREAM,0);
    if(sock < 0)
    {
        perror("error sock");
        return;
    }

    strcpy(ifreq.ifr_name,pDev);
    if(ioctl(sock,SIOCGIFHWADDR,&ifreq) < 0)
    {
        perror("error ioctl");
        return;
    }

    int i = 0;
    for(i = 0; i < 6; i++){
        sprintf(mac+i, "%c", (unsigned char)ifreq.ifr_hwaddr.sa_data[i]);
    }
    //mac[strlen(mac) - 1] = 0;
    printf("MAC: %s\n", mac);

    return (unsigned char*)mac;
}
int main(){
    char *dev, errbuf[PCAP_ERRBUF_SIZE];
    unsigned char selfMac[30];
    struct dev_ip di = getDeviceIp();
    GetSelfMac2(di.dev,selfMac);
    printf("%lu\n",di.ip);
    printf("%s\n",(di.dev));
    printf("%s\n",selfMac);

    struct send_par sp;
    sp.devname = di.dev;
    sp.macaddr = selfMac;
    sp.localip = di.ip;
    sp.mask = di.nmask; 
    printf("start\n");

    struct timeval tv;
    gettimeofday(&tv,NULL);
    long start = ((long)tv.tv_sec)*1000+(long)tv.tv_usec/1000;
    sp.stime = start;
    int err;
    err = pthread_create(&ntid, NULL, thr_rev, &sp);
    if(err != 0)
    {
        printf("can't create thread: %s\n", strerror(err));
    }  
    printf("end\n");
    sleep(1);
    sendArpPack(di.dev, selfMac, di.ip, di.nmask);
    sleep(10);

    printf("End test:%d\n",PCAP_ERRBUF_SIZE);
    
    //waitForArpReplyPacket(di.dev, selfMac, di.ip, di.nmask);
    
    return 1;
}


