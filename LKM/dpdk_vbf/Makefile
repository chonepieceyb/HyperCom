OBJ_NAME := dpdk_vbf

obj-m := ${OBJ_NAME}.o
#lkm_example-y := x.o

#KDIR ?= /home/chonepieceyb/CODING/Src/linux-6.0
KDIR_DBG ?= /mnt/disk1/yangbin/CODING/WorkSpace/linux_testbed/linux
KDIR ?= /lib/modules/6.6.0scmap/build

ifeq (${USE_DEBUG},1)
	ccflags-y += -DUSE_DEBUG
endif

ifeq (${USE_SIMD_HASH},1)
	ccflags-y += -DUSE_SIMD_HASH
endif

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