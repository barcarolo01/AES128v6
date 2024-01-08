#!/bin/bash
clear
dpu-upmem-dpurte-clang -DNR_TASKLETS=16 -DSTACK_SIZE_DEFAULT=2400 -O3 dpu.c -o dpu
gcc --std=c11 -maes -DNR_TASKLETS=16 -DRANKITER=1 -O3 host.c -o host `dpu-pkg-config --cflags --libs dpu`
./host