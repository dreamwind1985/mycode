#ifndef DPDK_PCAP_H
#define DPDK_PCAP_H
#include <stdio.h>
#include <stdbool.h>
#include <rte_config.h>
#include <rte_mbuf.h>
#include "v_string.h"
#include "common.h"
#ifndef uint32_t
#define uint32_t unsigned int 
#endif
struct content_array
{
	void *p;
	size_t len;
};

struct pcap_header
{
	unsigned int magic_number;//the value is 0xa1b2c3d4(ether big-endian or little-endian)
	unsigned short major_version;//the value is 2
	unsigned short minor_version;//the value is 4
	unsigned int timezone_offset;//the value is zero
	unsigned int time_stamp;//the value is zero
	unsigned int snap_lenth;// the maximun number of bytes per packet that wile be captured
	unsigned int linklayer_type;
};
typedef struct pcap_header pcap_header;


struct timev
{
	uint32_t tv_sec;
	uint32_t tv_usec; 
};
struct packet_header
{
	struct timev ts;
	uint32_t caplen;
	uint32_t len;
};

enum pkt_mem_status
{
	UNUSED = 0,
	CAPTURING,
	COMPLETE
};
struct pkt_mem
{
	uint32_t mem_size;
	uint32_t used_size;
	uint8_t * mem_ptr;
	uint32_t pkt_count;
	time_t start_time;
	enum pkt_mem_status status;
	struct pkt_mem *next;
};
struct dump_mem_list
{	
	uint32_t enable;	
	uint32_t dump_interval;
	uint32_t per_dump_counts;
	char dump_path[PATH_LEN];
	struct pkt_mem * head; 
	uint32_t count;
	struct pkt_mem * using_mem;
	
};


typedef struct content_array content_array;
//static char * get_pcap_file_path(char * filepath);
bool fill_file_header(void * p, size_t len, FILE *f);
bool fill_file_content(struct content_array *c_a,size_t c_a_len, FILE *f);
bool fill_file_end(void *p, size_t len, FILE *f);

bool fill_pcap_header(char *filepath);

bool save_single_packet(struct rte_mbuf *m, char * filepath );//this function is inefficient, just for test

struct dump_mem_list * get_g_dump_mem_list();
bool initialize_dump_mem();
struct pkt_mem * get_using_mem();
static struct pkt_mem * find_pkt_mem();

static struct pkt_mem *alloc_pkt_mem(size_t mem_size);
static void add_pkt_mem(struct pkt_mem *ptr);

bool dump_complete_packet();

static bool dump_packet2file(struct pkt_mem * ptr_pkt_mem);

static bool clear_pkt_mem_stat(struct pkt_mem * ptr_pkt_mem);

static bool free_pkt_mem(struct pkt_mem * ptr_pkt_mem);


bool save_packet(struct rte_mbuf *m, struct pkt_mem * ptr_pkt_mem);

#endif 
