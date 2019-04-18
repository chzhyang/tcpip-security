obj-m += nf_http.o
#obj-m += hello.o
#obj-m += send_pass.o
#obj-m += test.o
#obj-m += drop_all.o
#obj-m += drop_tcp.o

all:
		make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
clean:
		make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
