#include <stdio.h>
#include <ctype.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/io.h>
#include "dpdk_pcap.h"
#include "cur_time.h"
#include "parse_arg_s.h"
#include "read_conf.h"

#ifndef MAX_FILE_PATH
#define MAX_FILE_PATH PATH_LEN
#endif

#define MYMIN(a,b) ((a)<(b)?(a):(b))

#define MAX_PACKET_COUNT 65536

static char file_path[MAX_FILE_PATH];

static struct dump_mem_list  g_dump_mem_list; 

struct dump_mem_list * get_g_dump_mem_list()
{
	return &g_dump_mem_list; 
}

bool initialize_dump_mem()
{
	get_g_dump_mem_list() -> enable =  get_g_global_var()->m_pcapdump.enable;
	get_g_dump_mem_list() -> dump_interval = get_g_global_var()->m_pcapdump.dump_interval;
	
	get_g_dump_mem_list() -> per_dump_counts = MYMIN(MAX_PACKET_COUNT, get_g_global_var()->m_pcapdump.per_dump_counts);
	
	v_strncpy( get_g_dump_mem_list() -> dump_path, PATH_LEN, get_g_global_var()->m_pcapdump.dump_path, strlen(get_g_global_var()->m_pcapdump.dump_path));
	int strlength = strlen(get_g_dump_mem_list()->dump_path);
	if(get_g_dump_mem_list()->dump_path[strlength - 1] !='/' )
	{
		if(strlength < PATH_LEN - 1)
		{
			get_g_dump_mem_list()->dump_path[strlength] = '/';
			get_g_dump_mem_list()->dump_path[strlength + 1] = '\0';
		}
		else
		{
			printf("dump_path too long, use /tmp/ directory to dump\n");
			v_strncpy(get_g_dump_mem_list() -> dump_path, PATH_LEN, "/tmp/", strlen("/tmp/"));
		}
	}
	
	if(get_g_dump_mem_list()-> enable == 0) 
	{
		printf("dump packet function is not open\n");
		return true;
	}

	/*预分配2块内存*/
	struct pkt_mem * mem_p = (struct pkt_mem *)malloc(sizeof(struct pkt_mem));
	struct pkt_mem * mem_pn = (struct pkt_mem *)malloc(sizeof(struct pkt_mem));
	memset(mem_p,0,sizeof(struct pkt_mem));
	memset(mem_pn,0,sizeof(struct pkt_mem));
	mem_p->mem_size =  (get_g_dump_mem_list() -> per_dump_counts) * (2048 + sizeof(struct packet_header)) ;
	mem_pn->mem_size =  (get_g_dump_mem_list()->per_dump_counts) * (2048 + sizeof(struct packet_header)) ;
	mem_p->mem_ptr = (uint8_t *)malloc(mem_p->mem_size);
	mem_pn->mem_ptr = (uint8_t *)malloc(mem_pn->mem_size);
	if(mem_p->mem_ptr == NULL || mem_pn->mem_ptr == NULL)
	{
		printf("can't alloc memory for dump packet\n");
		return false;
	}
	get_g_dump_mem_list()->head = mem_p;
	get_g_dump_mem_list()->count++;
	mem_p->next = mem_pn;
	mem_pn->next = NULL;	
	get_g_dump_mem_list()->count++;
	get_g_dump_mem_list()->using_mem = get_g_dump_mem_list()->head;
 
	return true;
}


struct pkt_mem * get_using_mem()
{
	struct pkt_mem * retval = NULL;
	if(get_g_dump_mem_list() -> using_mem == NULL || get_g_dump_mem_list() -> using_mem -> status == COMPLETE || get_g_dump_mem_list() -> using_mem ->status == UNUSED)
	{
		retval = find_pkt_mem();	
		get_g_dump_mem_list() -> using_mem = retval; //更新using_mem
		return retval;
	}
	if(get_g_dump_mem_list() -> using_mem -> status == CAPTURING ) 
	{
		return get_g_dump_mem_list() -> using_mem;
	}
	return retval;
	
	
}

static struct pkt_mem * find_pkt_mem()
{
	struct pkt_mem * retval = NULL;
	struct pkt_mem * ptr_pkt_mem = get_g_dump_mem_list() -> head;
	while(ptr_pkt_mem != NULL)
	{
		if(ptr_pkt_mem -> status == UNUSED)
		{
			ptr_pkt_mem -> status =	CAPTURING;
			ptr_pkt_mem -> start_time = get_g_cur_time();
			printf("find_pkt_mem, g_cur_time = %d\n",get_g_cur_time());
			retval = ptr_pkt_mem;
			break; 
		}
		else if(ptr_pkt_mem -> status == COMPLETE)
		{
			ptr_pkt_mem = ptr_pkt_mem -> next;
			
		}
		else if(ptr_pkt_mem -> status == CAPTURING)
		{
			retval = ptr_pkt_mem;
			break;
		}
		else
		{
			printf("can't find an valid pkt_mem for dump packet\n");
			return NULL;
		}
	}
	if(retval == NULL)
	{
		retval = alloc_pkt_mem(get_g_dump_mem_list() -> per_dump_counts * (2048 + sizeof(struct packet_header))); 
	}
	return retval;
	
}

static struct pkt_mem * alloc_pkt_mem(size_t mem_size)
{
	if(get_g_dump_mem_list() -> count >= 15) return NULL; //最大分配15块内存
	struct pkt_mem * ptr_pkt_mem = (struct pkt_mem *)malloc(sizeof(struct pkt_mem));
	if(ptr_pkt_mem == NULL)
	{
		return NULL;
	}
	memset(ptr_pkt_mem, 0 , sizeof(struct pkt_mem));
	ptr_pkt_mem -> mem_size = mem_size;
	ptr_pkt_mem -> mem_ptr  = (uint8_t *)malloc(mem_size);
	ptr_pkt_mem -> status = CAPTURING;
	ptr_pkt_mem -> start_time = get_g_cur_time();	
	add_pkt_mem(ptr_pkt_mem);
	get_g_dump_mem_list() -> using_mem = ptr_pkt_mem;
	return ptr_pkt_mem;
}

static void add_pkt_mem(struct pkt_mem * ptr)
{
	struct pkt_mem *ptr_pkt_mem = get_g_dump_mem_list() -> head;
	if(ptr_pkt_mem == NULL) 
	{
		get_g_dump_mem_list() -> head = ptr;
		return;
	}
	while(ptr_pkt_mem -> next )
	{
		ptr_pkt_mem = ptr_pkt_mem -> next;
	}
	ptr -> next = NULL;
	ptr_pkt_mem ->next = ptr;
	get_g_dump_mem_list() -> count ++;

	return;
}

bool dump_complete_packet()
{
	struct pkt_mem *ptr_pkt_mem = get_g_dump_mem_list() -> head;
	uint32_t capture_flag = 0, unused_count = 0;
	while(ptr_pkt_mem != NULL)
	{
		if(ptr_pkt_mem -> status == COMPLETE)
		{
			printf("ptr_pkt_mem = %p, g_curtime_151=%d\n",ptr_pkt_mem, get_g_cur_time());
			dump_packet2file(ptr_pkt_mem);
			clear_pkt_mem_stat(ptr_pkt_mem);
		}
		else if(ptr_pkt_mem -> status == CAPTURING)
		{
			capture_flag = 1;	
		}
		else if(ptr_pkt_mem -> status == UNUSED)
		{
			unused_count++;
			if(capture_flag  && unused_count > 4)
			{
				free_pkt_mem(ptr_pkt_mem);
			}
		}else
		{
			break;
		}
		ptr_pkt_mem = ptr_pkt_mem->next;
		
	}
	ptr_pkt_mem = get_g_dump_mem_list() -> head;
	while(ptr_pkt_mem !=NULL)
	{
		if(ptr_pkt_mem -> status == CAPTURING)
		{
			printf("ptr_pkt_mem = %p, g_curtime_178= %d\n", ptr_pkt_mem,get_g_cur_time());
			if(ptr_pkt_mem -> pkt_count == 0)break;
			if(ptr_pkt_mem -> start_time + get_g_dump_mem_list() -> dump_interval < get_g_cur_time()) //暂定60秒dump一次
			{
				printf("start_time = %d",ptr_pkt_mem->start_time);
				ptr_pkt_mem-> status = COMPLETE;
			}
			break;
		}
		ptr_pkt_mem = ptr_pkt_mem->next;
	}
	return true;
}




#define DUMPFILENAME "dump_%d_server_%u_%u.pcap"
static bool dump_packet2file(struct pkt_mem * ptr_pkt_mem)
{
	char filepath[PATH_LEN] = {0};
	char filename[PATH_LEN] = {0};
	char tmp[64] = {0};
	int i=0;
	//snprintf(filepath,256,DUMPFILENAME,get_g_cur_time(), get_proc_id());
	v_strncpy(filepath, PATH_LEN, get_g_dump_mem_list() -> dump_path, strlen(get_g_dump_mem_list()->dump_path));
	snprintf(filename,256,DUMPFILENAME,get_g_cur_time(), get_proc_id(), i);
	if(strlen(filename) != s_str_append(filepath, PATH_LEN, filename, strlen(filename)))
	{
		printf("file_path too long to dump file\n");
		return false;
	}
	while(access(filepath, 0) == 0)//file is already exist
	{
		if(i < 10)
		{
			filepath[strlen(filepath)-6] = i + '0';
		}
		else if( i < 100)
		{
			snprintf(tmp,64,"%d",i);
			if(strlen(tmp) != s_str_append(filepath, PATH_LEN, tmp, strlen(tmp)))
			{
				printf("file_name too long to dump file, please check dump_pcap configuration\n");
				return false;	
			}
		}
		else
		{
			printf("i is too big to dump file, please check dump_pcap configuration\n");
			return false;
		}
		i++;
	}
	if(fill_pcap_header(filepath) == false)
	{
		printf("file %s write failure\n", filepath);
		return false;
	}
	FILE *fp = fopen(filepath, "a+");
	if(fp == NULL)
	{
		printf("file %s write failure\n", filepath);
		return false;
	}
	if(1 != fwrite((const void *)ptr_pkt_mem->mem_ptr, ptr_pkt_mem->used_size, 1, fp))
	{
		printf("wrtie file content error\n");
		fclose(fp);
		return false;
	}
	fflush(fp);
	fclose(fp);
	return true; 
}

static bool clear_pkt_mem_stat(struct pkt_mem * ptr_pkt_mem)
{
	ptr_pkt_mem -> used_size = 0;
	memset(ptr_pkt_mem->mem_ptr, 0,ptr_pkt_mem->mem_size);
	ptr_pkt_mem -> pkt_count = 0;
	ptr_pkt_mem -> start_time = 0;
	ptr_pkt_mem -> status = UNUSED;
	return true;
}

static bool free_pkt_mem(struct pkt_mem * ptr_pkt_mem)
{
	struct pkt_mem *p_pkt_mem = get_g_dump_mem_list() -> head;
	while(p_pkt_mem && p_pkt_mem->next)
	{
		if(p_pkt_mem->next == ptr_pkt_mem)
		{
			get_g_dump_mem_list()->count--;
			p_pkt_mem->next = ptr_pkt_mem->next;
			free(ptr_pkt_mem->mem_ptr);
			free(ptr_pkt_mem);
			return true;
		}
		p_pkt_mem = p_pkt_mem->next;
	}
	return true;
}

bool fill_file_header(void *p, size_t len, FILE *f)
{
	if(len != fwrite(p, 1, len, f))
	//if(len != write(f, (const void *)p, len))
	{
		printf("write file header error!\n");//just for debug and error log
		return false;
	}
	return true;
}

bool fill_file_content(content_array *c_a, size_t c_a_len, FILE *f)
{
	unsigned int i;
	for(i=0; i<c_a_len; i++)
	{
		if(c_a[i].len != fwrite((const void *)(c_a[i].p),1, c_a[i].len, f))
		{
			printf("wrtie file content error\n");
			return false;
		}
	}
	return true;
}

bool fill_file_end(void *p, size_t len, FILE *f)
{
	if(len != fwrite((const void *)p, 1,len, f))
	{
		printf("write file end error!\n");//just for debug and error log
		return false;
	}
	return true;
}


bool fill_pcap_header( char * filepath)
{
	struct pcap_header p_h={0xa1b2c3d4,2,4,0,0,0xFFFF,1};
	int len = sizeof(p_h);
	//FILE *fp = fopen(get_pcap_file_path(filepath), "w+b");
	FILE *fp = fopen(filepath, "w+b");
	if(fp == NULL)
	{
		printf("open pcap file error!\n");
		return false;
	}
	if(fill_file_header((void *)(&p_h), len, fp) == false)
	{
		fclose(fp);
		return false;
	}
	fclose(fp);
	return true;
}

bool save_packet(struct rte_mbuf *m, struct pkt_mem * ptr_pkt_mem)
{
	struct packet_header p_h;
	
	if(ptr_pkt_mem->used_size + sizeof(p_h) + p_h.len > ptr_pkt_mem -> mem_size)
	{
		ptr_pkt_mem -> status = COMPLETE;
		return false;
	}

	p_h.ts.tv_sec = get_g_cur_time();	
	p_h.ts.tv_usec = 0;
	p_h.caplen = m->pkt_len;
	p_h.len = m->pkt_len;

	memcpy((char *)ptr_pkt_mem->mem_ptr + ptr_pkt_mem->used_size, &p_h, sizeof(p_h));
	ptr_pkt_mem -> used_size += sizeof(p_h);
	memcpy((char *)ptr_pkt_mem->mem_ptr + ptr_pkt_mem->used_size, rte_pktmbuf_mtod(m, char *), p_h.len);
	ptr_pkt_mem -> used_size += p_h.len;
	ptr_pkt_mem -> pkt_count++;
	if(ptr_pkt_mem -> pkt_count >= get_g_dump_mem_list() -> per_dump_counts ) 
	{
		ptr_pkt_mem -> status = COMPLETE;
	}
	return true;

}

bool save_single_packet(struct rte_mbuf *m, char * filepath)
{
	//FILE *fp = fopen(get_pcap_file_path(filepath), "ab");
	FILE *fp = fopen(filepath, "ab");
	if(fp == NULL)
	{
		printf("open pcap file error, in save_single_packet!\n");
	}	
	struct content_array c_a[2];
	
	struct packet_header p_h;
	p_h.ts.tv_sec = time(NULL);	
	p_h.ts.tv_usec = 0;
	p_h.caplen = m->pkt_len;
	p_h.len = m->pkt_len;
	
	c_a[0].p = (void *)(&p_h);
	c_a[0].len = sizeof(p_h);

	c_a[1].p = rte_pktmbuf_mtod(m, void *);
	c_a[1].len = m->pkt_len;
	
	if( false == fill_file_content(c_a, 2, fp))
	{
		printf("save_single_packet error\n");
		fclose(fp);
		return false;
	}	
	fclose(fp);
	return true;
}


