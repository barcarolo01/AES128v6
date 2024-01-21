#!/bin/bash
clear
dpu-upmem-dpurte-clang -DNR_TASKLETS=16 -DSTACK_SIZE_DEFAULT=2400 -O3 dpu.c -o dpu
gcc --std=c11 -maes -DNR_TASKLETS=16 -DRANKITER=1 -O3 host2.c -o host2 `dpu-pkg-config --cflags --libs dpu`
./host2