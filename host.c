#define _POSIX_C_SOURCE 199309L
#include <wmmintrin.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "common.h"
#include <dpu.h>
#include <time.h>
#include <dpu_log.h>
#include "AdvEncStdNI.h"
#define MODUL9 9
#ifndef DPU_EXE
#define DPU_EXE "./dpu"
#endif

#ifndef RANKITER
#define RANKITER 1
#endif

#if RANKITER < 40
#define NRRANKS  RANKITER
#else
#define NRRANKS 40
#endif


#define BUFFER_SIZE BUFFER_SIZE_DPU*16

static char car='A';
unsigned char* bufferHost;
unsigned char* cryptedDPU;
unsigned char* cryptedNI;

unsigned char key[16] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};  
int8_t chiave[16] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};  
unsigned char RC[] = {0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36};
unsigned char EK[176];

void AES128_t(unsigned char* state)
{
		AddRoundKey(state,EK);
		for(int i=1;i<=10;++i)
		{		
			SubBytes(state,EK+16*i);
			ShiftRows(state,EK+16+i);
			if(i!=10){ MixColumns(state); }
			AddRoundKey(state,EK+16*i);
		}
} 

static inline double my_clock(void) {
  struct timespec t;
  clock_gettime(CLOCK_MONOTONIC_RAW, &t);
  return (1.0e-9 * t.tv_nsec + t.tv_sec);
}

void initBuffer(unsigned char* b, const int size)
{
	for(int i=0;i<size;++i)
	{
		b[i] = rand()%26 + 'A';
	}
}

void keyExpand(unsigned char* wb, const unsigned char* k){
	int i=0;
	for(i=0;i<44*4;++i)
	{
		if(i<16) { wb[i]=k[i]; }
		else
		{
			if(i%16 == 0)
			{
				//MSByte #3
				wb[i] = wb[i-16] ^ sbox[wb[i-3]] ^ RC[((i/16)-1)];
				++i;
				//MSByte #2 (no RC)
				wb[i] = wb[i-4*4] ^ sbox[wb[i-1*4+1]];
				++i;
				//MSByte #1 (no RC)
				wb[i] = wb[i-4*4] ^ sbox[wb[i-1*4+1]];
				++i;
				//MSByte #0 (no RC)
				wb[i] = wb[i-4*4] ^ sbox[wb[i-7]];
			}
			else{ wb[i] = wb[i-16] ^ wb[i-4]; }
		}
	}
}

int main()
{
	srand(time(NULL));
	bufferHost = malloc(BUFFER_SIZE);
	cryptedDPU = malloc(BUFFER_SIZE);
	cryptedNI = malloc(BUFFER_SIZE);
	aes128_load_key(chiave);	//Key expansion schedule for AES_NI
	keyExpand(EK,key);	//Key expansion process ofr DPU AES128 implementation
	initBuffer(bufferHost,BUFFER_SIZE);	//Initialize the buffer of length (BUFFER_SIZE ) with random bytes
	//Variables
	int numDPU=0,tot_DPU_buffer=0;
	int nrTMP,DPU_dpubuffers=0,NI_dpubuffers=0,t_dpubuffers=0,offHOST_t=0;
	int processedFileDPU=0;
	double initTime=0,endTime=0,toRanksTime=0,tmpTimer[5],fromRanksTime=0,ranksTime=0,HostTime=0,NI_time=0,t_time=0;
	struct dpu_set_t set, dpu, setRanks,rank;
	uint32_t each_dpu, each_rank;
	int  tmp,nr_state=0,clockPerSec=0;
	int offDPU=0, offDPUCrypted=0,offHOST=0,offHOSTcrypted=0;
	uint32_t nrDPUs_perRANK[256];

 	DPU_ASSERT(dpu_alloc_ranks(NRRANKS, NULL, &setRanks));	//Allocating DPUs
	DPU_ASSERT(dpu_get_nr_dpus(setRanks,&numDPU)); 
	DPU_ASSERT(dpu_load(setRanks, DPU_EXE, NULL));	//Loading DPU program
	DPU_ASSERT(dpu_broadcast_to(setRanks, "ExpandedKey", 0, EK, 176, DPU_XFER_DEFAULT)); //Broadcasting the expanded key to all DPUs
	int GBtoEncrypt=0;
	int nrRANKS=0;
	DPU_RANK_FOREACH(setRanks,rank,each_rank)
	{
		nrRANKS++;
		DPU_ASSERT(dpu_get_nr_dpus(rank,&nrTMP));
		nrDPUs_perRANK[each_rank] = nrTMP;
	}
	int NUM_MSG=0;
	for(int i=0;i<RANKITER;++i)
	{
		tot_DPU_buffer += nrDPUs_perRANK[i%nrRANKS];
	}
	
	printf("BUFFER_SIZE: %d MB\tBUFFER_SIZE_DPU: %d MB\tMALLOCSIZE: %d MB\n",BUFFER_SIZE/(1024*1024),BUFFER_SIZE_DPU/(1024*1024),BUFFER_SIZE/(1024*1024));
 	printf("DATA TO ENCRYPT: \033[1;32m%d MB\033[0m\n",(tot_DPU_buffer*BUFFER_SIZE_DPU)/(1024*1024)); 	
	printf("--Allocated %d DPUs (%d ranks)\t Using %d tasklets\n",numDPU,nrRANKS,NR_TASKLETS);

	initTime = my_clock();	//START Measuring performance
	//INIT DPU HASHING
	while(DPU_dpubuffers < tot_DPU_buffer)
	{
		tmpTimer[3]=my_clock();
		DPU_RANK_FOREACH(setRanks,rank,each_rank)
		{
			DPU_FOREACH(rank,dpu,each_dpu)
			{
				char* bufferDPU = bufferHost + DPU_dpubuffers;
				DPU_ASSERT(dpu_prepare_xfer(dpu,bufferDPU));	//Prepare
				DPU_dpubuffers++;
			} //end FOR_EACH
			DPU_ASSERT(dpu_push_xfer(rank,DPU_XFER_TO_DPU,"buffer",0,BUFFER_SIZE_DPU,DPU_XFER_ASYNC));	//Transfer	

		}	 //FOR_EACH_RANK
		dpu_sync(setRanks);
		toRanksTime += my_clock() - tmpTimer[3];
		
		tmpTimer[4]=my_clock();
		DPU_ASSERT(dpu_launch(setRanks, DPU_SYNCHRONOUS));
		ranksTime += my_clock()-tmpTimer[4];
		tmpTimer[5]=my_clock();

		DPU_RANK_FOREACH(setRanks,rank,each_rank)
		{
			DPU_FOREACH(rank,dpu,each_dpu)
			{
				DPU_ASSERT(dpu_prepare_xfer(dpu,cryptedDPU+offDPUCrypted));
				offDPUCrypted+=BUFFER_SIZE_DPU;
			}
			DPU_ASSERT(dpu_push_xfer(rank,DPU_XFER_FROM_DPU,"crypted",0,BUFFER_SIZE_DPU,DPU_XFER_ASYNC));
		}
	}
	dpu_sync(setRanks);
	fromRanksTime +=my_clock() - tmpTimer[5];
	endTime = my_clock();
	//END DPU HASHING
	
	
	tmpTimer[0]=my_clock();
	while(NI_dpubuffers < tot_DPU_buffer)
	{
		for(int i=0;i<nrRANKS;++i) //FOREACH_RANK
		{
			for(int j=0;j<nrDPUs_perRANK[i];++j) //FOREACH
			{
				offHOST = 0;
				offHOSTcrypted = 0;
				for(int p=0;p<BUFFER_SIZE_DPU;p+=16)
				{
					aes128_enc(bufferHost+offHOST+NI_dpubuffers,cryptedNI+offHOSTcrypted+NI_dpubuffers);
					offHOST+=16;
					offHOSTcrypted+=16;	
				}
				NI_dpubuffers++;
			}
		}
	}
	NI_time=my_clock() - tmpTimer[0];

	int z,err =0;
	if(NI_dpubuffers != DPU_dpubuffers) { err = 1; }
	else{ for(z=0;z<BUFFER_SIZE_DPU && err == 0;++z){if(cryptedDPU[z] != cryptedNI[z]){ err = 1; }} }
	
	if(err==0){ printf("[\033[1;32mOK\033[0m] %d MB encrypted\n",offHOST/(1024*1024)); }
	else{ printf("[\033[1;31mERROR\033[0m] Crypted buffers are NOT equals: z=%d\n",z);printf("OFF DPU: %d OFF HOST: %d\n",offDPU,offHOST); }
	
	printf("----Transf. to ranks: %.1f   RANKS TIME: %.1f   Transf. from ranks: %.1f\t (TOTAL %.1f)\n",1000.0*toRanksTime,1000.0*ranksTime,1000.0*fromRanksTime,1000.0*(endTime-initTime));
	int GB = (DPU_dpubuffers/1024)*(BUFFER_SIZE_DPU/1024);
	printf("----Encryption bandwidth: %.1f GB/s (%.1f Gbps)\n",GB/(endTime-initTime),(GB*8)/(endTime-initTime));
	printf("----AES_NI time on HOST CPU: %.1f ms.\n", 1000.0*(NI_time));
	printf("-----------------------------------------------------\n");
	dpu_free(setRanks);
	free(bufferHost);
	free(cryptedDPU);
	free(cryptedNI);	 
    return 0;
}
