obj-m += vuln.o

KDIR := /home/veritas/linux-5.15.103
# KDIR := /lib/modules/`uname -r`/build

PWD := $(shell pwd)

.PHONY: default

default:
	make -C $(KDIR) M=$(PWD) modules && \
	cp vuln.ko .. && \
	rm -rf .*.cmd *.symvers *.order *.ko *.mod* *.o

clean:
	rm -rf *.o \.* .cmd *.ko *.mod.c .tmp_versions