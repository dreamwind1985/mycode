#include<stdio.h>
#include<ctype.h>
#include "hexprint.h"

void hex_print(char *p, size_t n)
{
	char HEX[]="0123456789ABCDEF";
	unsigned int i,j,count;
	j=0;
	i=0;
	count=0;
	while(j < n)
	{
		count++;
		printf("0x%d\t",count);
		if(j+16<n){
			for(i=0;i<16;i++)
			{
				printf("0x%c%c ",HEX[(p[j+i]&0xF0) >> 4],HEX[p[j+i]&0xF]);
			}
			printf("\t");
			for(i=0;i<16;i++)
			{
				printf("%c",isprint(p[j+i])?p[j+i]:'.');
			}
			printf("\n");
			j = j+16;
		}
		else
		{
			for(i=0;i<n-j;i++)
			{
				printf("0x%c%c ",HEX[(p[j+i]&0xF0) >> 4],HEX[p[j+i]&0xF]);
			}
			printf("\t");
			for(i=0;i<n-j;i++)
			{
				printf("%c",isprint(p[j+i])?p[j+i]:'.');
			}
			printf("\n");
			break;
		}
	}
}

/*
int test()
{
	char *p;
	int i[]={1,1000,1000000,0xffffff,0xaaaaa,0x67686970};
	p=(char *)i;
	hex_print(p,sizeof(i)*4);	
	return 0;
}*/
