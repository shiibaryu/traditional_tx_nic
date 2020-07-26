#ifndef _NETTLP_MSG_H_
#define _NETTLP_MSG_H_

#include "nettlp_sem.h"

#define Q_VECTORS	8
#define TX_QUEUES   	4
#define RX_QUEUES   	4

#define DESC_ENTRY_SIZE  512

#define BAR4_TX_DESC_OFFSET 	24	
#define BAR4_RX_DESC_OFFSET	56
#define BASE_SUM	64

#define TX_NT_SIZE 	4
#define RX_NT_SIZE 	4

#define MRRS		512
#define MPS		256

#define likely(x) __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)

#define is_mwr_addr_tx_desc_ptr(bar4,a)		\
	(a - bar4 <= BAR4_TX_DESC_OFFSET)

#define is_mwr_addr_rx_desc_ptr(bar4,a)		\
	(a - bar4 <= BAR4_RX_DESC_OFFSET)

struct tx_desc_ctl{
	uint32_t tx_tail_idx;
	uintptr_t tx_desc_tail;
	char *current_shm;
};

struct rx_desc_ctl{
	uint32_t head;
	uint32_t tail;
	uintptr_t desc_head;
	uintptr_t desc_tail;
};

struct shm_rx_ctl{
	int idx;
	int sem_id;
	char *shm;
	union semun *semu;
	int *rx_state;
	uintptr_t *rx_desc_base;
	pthread_t tid;
	struct descriptor *desc;
	struct nettlp_msix *rx_irq;
	struct rx_desc_ctl *rxd_ctl;
	struct nettlp *rx_nt;
};

struct descriptor{
	uint64_t addr;
	uint64_t length;
} __attribute__((packed));

struct nettlp_mnic{
	int tx_sem_id[TX_QUEUES];
	int rx_sem_id[RX_QUEUES];

	struct sembuf tx_ops[TX_QUEUES];
	union semun tx_sem[TX_QUEUES];
	struct sembuf rx_ops[RX_QUEUES][2];
	union semun rx_sem[RX_QUEUES];
	char *tx_shm[TX_QUEUES];
	char *rx_shm[RX_QUEUES];

	uintptr_t bar4_start;
	int tx_queue_id;
	uintptr_t *tx_desc_base;
	int rx_queue_id;
	uintptr_t *rx_desc_base;

	//struct nettlp rx_nt[RX_NT_SIZE];
	//struct nettlp *rx_dma_read_nt;
	struct nettlp tx_nt[TX_QUEUES];
	struct nettlp rx_nt[RX_QUEUES];
	struct nettlp_msix *tx_irq,*rx_irq;

	struct descriptor *tx_desc[TX_QUEUES];
	struct descriptor *rx_desc[RX_QUEUES];
	struct tx_desc_ctl *tx_desc_ctl;
	struct rx_desc_ctl *rx_desc_ctl;
	
	int rx_state[RX_QUEUES];
#define RX_STATE_INIT	0
#define RX_STATE_READY  1
#define RX_STATE_BUSY   2
#define RX_STATE_DONE	3
	uintptr_t *rx_desc_addr;
#define _GNU_SOURCE
};

#endif

#ifndef NDEBUG
#define debug(fmt, ...) do {\
	fprintf(stderr, "[DEBUG] %s:%d %s(): " fmt "\n", __FILE__, __LINE__, __func__, ##__VA_ARGS__);\
} while(0)
#else
#define debug(fmt, ...) do {} while(0)
#undef assert
#define assert(expr) (void) (expr)
#endif

#define info(fmt, ...) do {\
	fprintf(stdout, "[INFO ] %s:%d %s(): " fmt "\n", __FILE__, __LINE__, __func__, ##__VA_ARGS__);\
} while(0)


