#include "common.h"
#include "bpf_skel/test_tzcnt.skel.h"

#define XDP_IF "ens4np0"

int main()
{
	BPF_XDP_SKEL_LOADER(test_tzcnt, XDP_IF, xdp_main, XDP_FLAGS_DRV_MODE)
}
