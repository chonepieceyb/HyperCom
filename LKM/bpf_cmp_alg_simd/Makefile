OBJ_NAME := bpf_cmp_alg_simd
GCC_VERSION ?= 13
CC_SIMD_OPTS ?= -mavx2 -mbmi

obj-m := ${OBJ_NAME}.o

ccflags-y += -I/usr/lib/gcc/x86_64-linux-gnu/$(GCC_VERSION)/include $(CC_SIMD_OPTS)

KDIR_DBG ?= /mnt/disk1/yangbin/CODING/WorkSpace/linux_testbed/linux
KDIR ?= /lib/modules/$(shell uname -r)/build

default:
	bear -- make -C $(KDIR) M=$(PWD) modules
dbg:
	bear -- make -C $(KDIR_DBG) M=$(PWD) modules
clean:
	make -C $(KDIR) M=$(PWD) clean
test:
	# We put a — in front of the rmmod command to tell make to ignore
	# an error in case the module isn't loaded.
	-sudo rmmod $(OBJ_NAME)
	# Clear the kernel log without echo
	sudo dmesg -C
	# Insert the module
	sudo insmod $(OBJ_NAME).ko
	# Display the kernel log
	sudo dmesg
rm: 
	-sudo rmmod $(OBJ_NAME)
	sudo dmesg
