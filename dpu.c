#include <stdio.h>
#include <mram.h>
#include <stdlib.h>
#include "common.h"
#include <stdint.h>
#include <mram.h>
#include <perfcounter.h>
#include <defs.h>

#define CACHE_SIZE 2048

__mram char buffer[BUFFER_SIZE_DPU];
__mram char crypted[BUFFER_SIZE_DPU];
__host __dma_aligned unsigned char ExpandedKey[176];

void AES128_t(unsigned char* state)
{
		AddRoundKey(state,ExpandedKey);
		for(int i=1;i<=10;++i)
		{		
			SubBytes(state,ExpandedKey+16*i);
			ShiftRows(state,ExpandedKey+16+i);
			if(i!=10){ MixColumns(state); }
			AddRoundKey(state,ExpandedKey+16*i);
		}
} 


int main()
{		
	int k=0,j=0,offset;
	int offset_buffer = j*(CACHE_SIZE*NR_TASKLETS)+me()*CACHE_SIZE;
	unsigned char cache[2048];

	for(j=0;j*(CACHE_SIZE*NR_TASKLETS)+me()*CACHE_SIZE<BUFFER_SIZE_DPU;++j)
	{
		offset_buffer = j*(CACHE_SIZE*NR_TASKLETS)+me()*CACHE_SIZE;
		mram_read(buffer+offset_buffer,cache,CACHE_SIZE);	
		for(offset=0; offset < CACHE_SIZE; offset+=16)
		{
				AES128_t(cache+offset);
		}
		mram_write(cache,crypted+offset_buffer,CACHE_SIZE);
	}
	
    return 0;
}
