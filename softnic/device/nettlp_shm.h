#ifndef _NETTLP_SHM_H_
#define _NETTLP_SHM_H_

#define TX1_SHM_PATH	"/tx1_shm"
#define TX2_SHM_PATH	"/tx2_shm"
#define TX3_SHM_PATH	"/tx3_shm"
#define TX4_SHM_PATH	"/tx4_shm"
#define RX1_SHM_PATH	"/rx1_shm"
#define RX2_SHM_PATH	"/rx2_shm"
#define RX3_SHM_PATH	"/rx3_shm"
#define RX4_SHM_PATH	"/rx4_shm"

#define TX_SHM_SIZE	1500*512  //MAX_PACKET_SIZE*NUM_OF_DESCRIPTOR
#define RX_SHM_SIZE	1500*512  //MAX_PACKET_SIZE*NUM_OF_DESCRIPTOR

#define BESS_MAX_PKT	32
#endif
