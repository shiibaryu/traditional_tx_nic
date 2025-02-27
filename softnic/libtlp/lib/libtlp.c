/*
 * libtlp.c
 */
#define _GNU_SOURCE
#include <stdio.h>	/* for debug */
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <poll.h>
#include <sched.h>
#include <pthread.h>

#include <libtlp.h>
#include <tlp.h>


#ifdef __APPLE__

#include <libkern/OSByteOrder.h>

#define htobe16(x) OSSwapHostToBigInt16(x)
#define htole16(x) OSSwapHostToLittleInt16(x)
#define be16toh(x) OSSwapBigToHostInt16(x)
#define le16toh(x) OSSwapLittleToHostInt16(x)

#define htobe32(x) OSSwapHostToBigInt32(x)
#define htole32(x) OSSwapHostToLittleInt32(x)
#define be32toh(x) OSSwapBigToHostInt32(x)
#define le32toh(x) OSSwapLittleToHostInt32(x)

#define htobe64(x) OSSwapHostToBigInt64(x)
#define htole64(x) OSSwapHostToLittleInt64(x)
#define be64toh(x) OSSwapBigToHostInt64(x)
#define le64toh(x) OSSwapLittleToHostInt64(x)

#endif


#define LIBTLP_CPL_TIMEOUT	500	/* msec */


/* for debug use */
static void hexdump(void *buf, int len)
{
        int n;
        unsigned char *p = buf;

        printf("Hex dump\n");

        for (n = 0; n < len; n++) {
                printf("%02x", p[n]);

                if ((n + 1) % 2 == 0)
                        printf(" ");
                if ((n + 1) % 32 == 0)
                        printf("\n");
        }
        printf("\n\n");
}


/* utilities for parsing TLP headers */

int tlp_calculate_lstdw(uintptr_t addr, size_t count)
{
	uintptr_t end, end_start, start;

	start = (addr >> 2) << 2;
	end = addr + count;
	if ((end & 0x3) == 0)
		end_start = end - 4;
	else
		end_start = (end >> 2) << 2;

	/* corner case. count is smaller than 8 */
	if (end_start <= start)
		end_start = addr + 4;
	if (end < end_start)
		return 0;

	return ~(0xF << (end - end_start)) & 0xF;
}

int tlp_calculate_fstdw(uintptr_t addr, size_t count)
{
	uint8_t be = 0xF;

	if (count < 4)
		be = ~(0xF << count) & 0xF;

	return (be << (addr & 0x3)) & 0xF;
}

int tlp_calculate_length(uintptr_t addr, size_t count)
{
	size_t len = 0;
	uintptr_t start, end;

	start = addr & 0xFFFFFFFFFFFFFFFc;
	end = addr + count;

	len = (end - start) >> 2;

	if ((end - start) & 0x3)
		len++;

	return len;
}


uintptr_t tlp_mr_addr(struct tlp_mr_hdr *mh)
{
	int n;
	uintptr_t addr;
	uint32_t *addr32;
	uint64_t *addr64;

	if (tlp_is_3dw(mh->tlp.fmt_type)) {
		addr32 = (uint32_t *)(mh + 1);
		addr = be32toh(*addr32);
	} else {
		addr64 = (uint64_t *)(mh + 1);
		addr = be64toh(*addr64);
	}
	
	/* move forard the address in accordance with the 1st DW BE */
	if (mh->fstdw && mh->fstdw != 0xF) {
		for (n = 0; n < 4; n++) {
			if ((mh->fstdw & (0x1 << n)) == 0) {
				addr += 1;
			} else
				break;
		}
	}

	return addr;
}

int tlp_mr_data_length(struct tlp_mr_hdr *mh)
{
	int n;
	uint32_t len;

	len = tlp_length(mh->tlp.falen) << 2;

	if (mh->fstdw && mh->fstdw != 0xF) {
		for (n = 0; n < 4; n++) {
			if ((mh->fstdw & (0x1 << n)) == 0) {
				len--;
			}
		}
	}

	if (mh->lstdw && mh->lstdw != 0xF) {
		for (n = 0; n < 4; n++) {
			if ((mh->lstdw & (0x8 >> n)) == 0) {
				len--;
			} else
				break;
		}
	}

	return len;
}

void *tlp_mwr_data(struct tlp_mr_hdr *mh)
{
	int n;
	void *p;

	p = tlp_is_3dw(mh->tlp.fmt_type) ?
		((char *)(mh + 1)) + 4 : ((char *)(mh + 1)) + 8;

	if (mh->fstdw && mh->fstdw != 0xF) {
		for (n = 0; n < 4; n++) {
			if ((mh->fstdw & (0x1 << n)) == 0) {
				p++;
			} else
				break;
		}
	}

	return p;
}

int tlp_cpld_data_length(struct tlp_cpl_hdr *ch)
{
	/* if this is last CplD, byte count is actual byte length */
	if (tlp_length(ch->tlp.falen) ==
	    ((ch->lowaddr & 0x3) + tlp_cpl_bcnt(ch->stcnt) + 3) >> 2)
		return tlp_cpl_bcnt(ch->stcnt);

	/* if not, length - padding due to 4DW alignment */
	return (tlp_length(ch->tlp.falen) << 2) - (ch->lowaddr & 0x3);
}

void *tlp_cpld_data(struct tlp_cpl_hdr *ch)
{
	void *p;

	p = tlp_is_3dw(ch->tlp.fmt_type) ?
		((char *)(ch + 1)) + 4 : ((char *)(ch + 1)) + 8;

	/* shift for padding due to 4DW alignment */
	p += (ch->lowaddr & 0x3);
	return p;
}


/*
 * nettlp
 */

static int nettlp_create_udp_socket(struct in_addr remote_addr,
				    uint16_t remote_port,
				    struct in_addr local_addr,
				    uint16_t local_port)
{
	int fd, ret;
	struct sockaddr_in saddr;

	fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (fd < 0)
		return fd;

	/* bind to local address */
	memset(&saddr, 0, sizeof(saddr));
	saddr.sin_family = AF_INET;
	saddr.sin_addr = local_addr;
	saddr.sin_port = htons(local_port);
	ret = bind(fd, (struct sockaddr *)&saddr, sizeof(saddr));
	if (ret < 0)
		return ret;
	
	/* connect to remote address */
	memset(&saddr, 0, sizeof(saddr));
	saddr.sin_family = AF_INET;
	saddr.sin_addr = remote_addr;
	saddr.sin_port = htons(remote_port);
	ret = connect(fd, (struct sockaddr *)&saddr, sizeof(saddr));
	if (ret < 0)
		return ret;

	return fd;
}

int nettlp_init(struct nettlp *nt)
{
	int fd;

	switch (nt->dir) {
	case DMA_ISSUED_BY_LIBTLP:
		nt->port = NETTLP_LIBTLP_PORT_BASE + nt->tag;
		break;
	case DMA_ISSUED_BY_ADAPTER:
		nt->port = NETTLP_ADAPTER_PORT_BASE + (nt->tag & 0x0F);
		break;
	default:
		errno = EINVAL;
		return -1;
	}

	fd = nettlp_create_udp_socket(nt->remote_addr, nt->port,
				      nt->local_addr, nt->port);
	if (fd < 0)
		return fd;

	nt->sockfd = fd;

	return 0;
}


/*
 * Direct Memoy Access API
 */

static ssize_t libtlp_read_cpld(struct nettlp *nt, void *buf,
				size_t count)
{
	int ret = 0;
	ssize_t received;
	char rest[16];	/* additional buffer for gap of 4WD-aligned bytes */
	struct pollfd x[1];
	struct iovec iov[4];
	struct nettlp_hdr nh;
	struct tlp_cpl_hdr ch;

	iov[0].iov_base = &nh;
	iov[0].iov_len = sizeof(nh);
	iov[1].iov_base = &ch;
	iov[1].iov_len = sizeof(ch);
	iov[3].iov_base = rest;
	iov[3].iov_len = sizeof(rest);
	x[0].fd = nt->sockfd;
	x[0].events = POLLIN;

	received = 0;

	while (1) {

		ret = poll(x, 1, LIBTLP_CPL_TIMEOUT);
		if (ret < 0)
			goto err_out;

		if (ret == 0) {
			ret = -1;
			errno = ETIME;
			goto err_out;
		}

		if (!(x[0].revents & POLLIN))
			goto err_out;

		iov[2].iov_base = buf + received;
		iov[2].iov_len = count - received;
		ret = readv(nt->sockfd, iov, 4);
		if (ret < 0)
			goto err_out;

		if (!(tlp_is_cpl(ch.tlp.fmt_type) &&
		      tlp_is_w_data(ch.tlp.fmt_type))) {
			/* invalid data type */
			errno = EBADMSG;
			ret = -1;
			goto err_out;
		}

		if (tlp_cpl_status(ch.stcnt) != TLP_CPL_STATUS_SC) {
			switch (tlp_cpl_status(ch.stcnt)) {
			case TLP_CPL_STATUS_UR:
				errno = EOPNOTSUPP;
				ret = -1;
				goto err_out;
			case TLP_CPL_STATUS_CRS:
				errno = EINVAL;
				ret = -1;
				goto err_out;
			case TLP_CPL_STATUS_CA:
				errno = ECONNABORTED;
				ret = -1;
				goto err_out;
			}
		}
		
		if (ch.lowaddr & 0x3) {
			/* note: iov[2].iov_len must be identical with
			 * byte count. current buffer layout is:
			 *
			 * |-low & 0x3-|----byte cnt----|-Last BE-|
			 * |----------------|---------------------------|
			 *       iov[2]                iov[3]
			 *
			 * So, move bytecnt bytes from iov[2].base +
			 * (lowaddr & 0x3) across iov[2] and iov[3].
			 * 
			 * or
			 *
			 * |-low & 0x3-|-BC-|
			 * |----|-------------------------------------|
			 * iov[2]                iov[3]
			 *
			 * iov[2].len is shorter than (lowaddr & 0x3).
			 * mv bytecnt bytes from iov[3] + ((lowaddr &
			 * 0x3) - iov[2].len) to iov[2].
			 */
			int diff = iov[2].iov_len - (ch.lowaddr & 0x3);

			if (diff > 0) {
				memmove(iov[2].iov_base,
					iov[2].iov_base + (ch.lowaddr & 0x3),
					diff);

				memmove(iov[2].iov_base + diff,
					iov[3].iov_base,
					ch.lowaddr & 0x3);
			} else {
				diff = (ch.lowaddr & 0x3) - iov[2].iov_len;
				memmove(iov[2].iov_base,
					iov[3].iov_base + diff,
					tlp_cpl_bcnt(ch.stcnt));
			}
		}

		if (tlp_length(ch.tlp.falen) ==
		    ((ch.lowaddr & 0x3) + tlp_cpl_bcnt(ch.stcnt) + 3) >> 2) {

			/* last CplD.
			 * see http://xillybus.com/tutorials/
			 * pci-express-tlp-pcie-primer-tutorial-guide-1
			 */
			received += tlp_cpl_bcnt(ch.stcnt);
			break;
		} else {
			received += tlp_length(ch.tlp.falen) << 2;
		}
	}

out:
	return received;

err_out:
	return ret;
}


ssize_t dma_read(struct nettlp *nt, uintptr_t addr, void *buf, size_t count)
{
	int ret;
	struct iovec iov[3];
	struct nettlp_hdr nh;
	struct tlp_mr_hdr mh;
	uint64_t dst_addr64;
	uint32_t dst_addr32;

	memset(&nh, 0, sizeof(nh));
	memset(&mh, 0, sizeof(mh));

	iov[0].iov_base = &nh;
	iov[0].iov_len = sizeof(nh);
	iov[1].iov_base = &mh;
	iov[1].iov_len = sizeof(mh);

	/* build memory read request  */
	tlp_set_type(mh.tlp.fmt_type, TLP_TYPE_MRd);
	if (addr < UINT32_MAX) {
		tlp_set_fmt(mh.tlp.fmt_type, TLP_FMT_3DW, TLP_FMT_WO_DATA);
		dst_addr32 = htobe32(addr & 0xFFFFFFFC);
		iov[2].iov_base = &dst_addr32;
		iov[2].iov_len = sizeof(dst_addr32);
	} else {
		tlp_set_fmt(mh.tlp.fmt_type, TLP_FMT_4DW, TLP_FMT_WO_DATA);
		dst_addr64 = htobe64(addr & 0xFFFFFFFFFFFFFFFC);
		iov[2].iov_base = &dst_addr64;
		iov[2].iov_len = sizeof(dst_addr64);
	}
	mh.requester = ntohs(nt->requester);
	mh.tag = nt->tag;
	mh.lstdw = tlp_calculate_lstdw(addr, count);
	mh.fstdw = tlp_calculate_fstdw(addr, count);
	tlp_set_length(mh.tlp.falen, tlp_calculate_length(addr, count));
	

	ret = writev(nt->sockfd, iov, 3);
	if (ret < 0)
		return ret;

	return libtlp_read_cpld(nt, buf, count);
}

ssize_t dma_write(struct nettlp *nt, uintptr_t addr, void *buf, size_t count)
{
	int ret, n;
	char pad[4] = { 0, 0, 0, 0 };
	struct iovec iov[6];
	struct nettlp_hdr nh;
	struct tlp_mr_hdr mh;
	uint64_t dst_addr64;
	uint32_t dst_addr32;

	memset(&nh, 0, sizeof(nh));
	memset(&mh, 0, sizeof(mh));

	iov[0].iov_base = &nh;
	iov[0].iov_len = sizeof(nh);
	iov[1].iov_base = &mh;
	iov[1].iov_len = sizeof(mh);
	iov[3].iov_base = pad;
	iov[3].iov_len = 0;	/* if needed, increment for padding */
	iov[4].iov_base = buf;
	iov[4].iov_len = count;
	iov[5].iov_base = pad;
	iov[5].iov_len = 0;	/* if needed, increment for padding */


	/* build memory write request */
	tlp_set_type(mh.tlp.fmt_type, TLP_TYPE_MWr);
	if (addr < UINT32_MAX) {
		tlp_set_fmt(mh.tlp.fmt_type, TLP_FMT_3DW, TLP_FMT_W_DATA);
		dst_addr32 = htobe32(addr & 0xFFFFFFFC);
		iov[2].iov_base = &dst_addr32;
		iov[2].iov_len = sizeof(dst_addr32);
	} else {
		tlp_set_fmt(mh.tlp.fmt_type, TLP_FMT_4DW, TLP_FMT_W_DATA);
		dst_addr64 = htobe64(addr & 0xFFFFFFFFFFFFFFFC);
		iov[2].iov_base = &dst_addr64;
		iov[2].iov_len = sizeof(dst_addr64);
	}
	mh.requester = ntohs(nt->requester);
	mh.tag = nt->tag;
	mh.lstdw = tlp_calculate_lstdw(addr, count);
	mh.fstdw = tlp_calculate_fstdw(addr, count);
	tlp_set_length(mh.tlp.falen, tlp_calculate_length(addr, count));

	/* XXX:
	 * 
	 * 1st DW BE is used and not 0xF, move the buffer, if 1st DW
	 * is xx10, x100, or 1000. It needs padding.
	 */
	if (mh.fstdw && mh.fstdw != 0xF) {
		for (n = 0; n < 3; n++) {
			if ((mh.fstdw & (0x1 << n)) == 0) {
				/* this byte is not used. padding! */
				iov[3].iov_len++;
			}
		}
	}

	if (mh.lstdw && mh.lstdw != 0xF) {
		for (n = 0; n < 3; n++) {
			if ((mh.lstdw & (0x8 >> n)) == 0) {
				/* this byte is not used, padding! */
				iov[5].iov_len++;
			}
		}
	}


	ret = writev(nt->sockfd, iov, 6);
	if (ret < 0)
		return ret;

	if (ret < (iov[0].iov_len + iov[1].iov_len + iov[2].iov_len)) {
		/* failed to write the whole packet */
		return -2;
	}

	return ret - (iov[0].iov_len + iov[1].iov_len + iov[2].iov_len
		      + iov[3].iov_len + iov[5].iov_len);
}


ssize_t
dma_read_aligned(struct nettlp *nt, uintptr_t addr, void *buf,
		 size_t count, size_t mrrs)
{
	uintptr_t dma_addr;
	size_t len, done;
	ssize_t ret, dma_len;

	done = 0;
	dma_addr = addr;
	dma_len = count;

	do {
		len = dma_len < mrrs ? dma_len : mrrs;
		ret = dma_read(nt, dma_addr, buf + done, len);
		if (ret < 0)
			return ret;

		/* for next iteration */
		done += ret;
		dma_addr += ret;
		dma_len -= ret;

	} while (dma_len > 0);

	return ret;
}

ssize_t
dma_write_aligned(struct nettlp *nt, uintptr_t addr, void *buf,
		  size_t count, size_t mps)
{
	uintptr_t dma_addr;
	size_t len, done;
	ssize_t ret, dma_len;

	done = 0;
	dma_addr = addr;
	dma_len = count;

	do {
		len = dma_len < mps ? dma_len : mps;
		ret = dma_write(nt, dma_addr, buf + done, len);
		if (ret < 0)
			return ret;

		/* for next iteration */
		done += ret;
		dma_addr += ret;
		dma_len -= ret;

	} while (dma_len > 0);

	return ret;
}

/*
 * Callback API for pseudo memory process
 */

struct nettlp_mqpoll_arg{
	void *arg;
	int cpu;
	int offset;
	struct nettlp *nt;
	struct pollfd x;
	struct nettlp_cb *cb;
};

static int stop_flag = 0;

int nettlp_run_cb(struct nettlp **nt, int nnts,
		  struct nettlp_cb *cb, void *arg)
{
	int ret = 0, n;
	ssize_t received;
	struct pollfd x[NETTLP_CB_MAX_NTS];
	char buf[4096];
	struct nettlp_hdr *nh;
	struct tlp_hdr *th;
	struct tlp_mr_hdr *mh;
	struct tlp_cpl_hdr *ch;

	if (nnts > NETTLP_CB_MAX_NTS) {
		errno = -EINVAL;
		return -1;
	}

	for (n = 0; n < nnts; n++) {
		x[n].fd = nt[n]->sockfd;
		x[n].events = POLLIN;
	}

	while (1) {

		if (stop_flag)
			break;

		ret = poll(x, nnts, LIBTLP_CPL_TIMEOUT);
		if (ret < 0)
			break;

		if (ret == 0)
			continue;	

		for (n = 0; n < nnts; n++) {

			if (!(x[n].revents & POLLIN))
				continue;

			ret = read(nt[n]->sockfd, buf, sizeof(buf));
			if (ret < 0)
				break;

			nh = (struct nettlp_hdr *)buf;
			th = (struct tlp_hdr *)(nh + 1);
			mh = (struct tlp_mr_hdr *)th;
			ch = (struct tlp_cpl_hdr *)th;

			if (tlp_is_mrd(th->fmt_type) && cb->mrd) {
				cb->mrd(nt[n], mh, arg);
			} else if (tlp_is_mwr(th->fmt_type) && cb->mwr) {

				cb->mwr(nt[n], mh, tlp_mwr_data(mh),
					tlp_mr_data_length(mh), arg);

			} else if (tlp_is_cpl(th->fmt_type) &&
				   tlp_is_wo_data(th->fmt_type) && cb->cpl) {

				cb->cpl(nt[n], ch, arg);

			} else if (tlp_is_cpl(th->fmt_type) &&
				   tlp_is_w_data(th->fmt_type) && cb->cpld) {

				cb->cpld(nt[n], ch, tlp_cpld_data(ch),
					 tlp_cpld_data_length(ch), arg);
			} else if (cb->other) {
				cb->other(nt[n], th, arg);
			}
		}
	}

	return ret;
}

/*
void *nettlp_mq_poll(void *arg)
{
	int n= 0;
	int ret = 0;
	ssize_t received;
	char buf[4096];
	struct nettlp_hdr *nh;
	struct tlp_hdr *th;
	struct tlp_mr_hdr *mh;
	struct tlp_cpl_hdr *ch;

	struct nettlp_mqpoll_arg *mqp = arg;
	struct pollfd x[1] = {{.fd = mqp->x.fd, .events = POLLIN}};
	struct nettlp *nt = mqp->nt;
	struct nettlp_cb *cb = mqp->cb;

	while (1) {

		if (stop_flag)
			break;

		ret = poll(x, 1 , LIBTLP_CPL_TIMEOUT);
		if (ret < 0)
			break;

		if (ret == 0)
			continue;	

		if (!(x[n].revents & POLLIN))
			continue;

		ret = read(nt->sockfd, buf, sizeof(buf));
		if (ret < 0)
			break;

		nh = (struct nettlp_hdr *)buf;
		th = (struct tlp_hdr *)(nh + 1);
		mh = (struct tlp_mr_hdr *)th;
		ch = (struct tlp_cpl_hdr *)th;

		if (tlp_is_mrd(th->fmt_type) && cb->mrd) {
			cb->mrd(nt, mh, mqp->arg);
		} else if (tlp_is_mwr(th->fmt_type) && cb->mwr) {
			cb->mwr(nt, mh, tlp_mwr_data(mh),
				tlp_mr_data_length(mh), mqp->arg);
		} else if (tlp_is_cpl(th->fmt_type) &&
			tlp_is_wo_data(th->fmt_type) && cb->cpl) {
				cb->cpl(nt, ch, mqp->arg);
		} else if (tlp_is_cpl(th->fmt_type) &&
			tlp_is_w_data(th->fmt_type) && cb->cpld) {
				cb->cpld(nt, ch, tlp_cpld_data(ch),
						tlp_cpld_data_length(ch), mqp->arg);
		} else if (cb->other) {
			cb->other(nt, th, mqp->arg);
		}
	}
}

int nettlp_run_cb(struct nettlp **nt,int nnts,
		struct nettlp_cb *cb, void *arg)
{
	int ret = 0,n;
	pthread_t sock_tid[nnts];
	cpu_set_t target_cpu_set;
	struct nettlp_mqpoll_arg mtq[nnts];
	struct nettlp_mnic *mnic = arg;

	if(nnts > NETTLP_CB_MAX_NTS){
		errno = -EINVAL;
		return -1;
	}

	for(n = 0; n < nnts; n++){
		mtq[n].nt = nt[n];
		mtq[n].arg = arg;
		mtq[n].offset = n;
		mtq[n].cb = cb;
		mtq[n].x.fd = nt[n]->sockfd;
		mtq[n].x.events = POLLIN;
		mtq[n].cpu = nt[n]->tag;

		pthread_create(&sock_tid[n],NULL,nettlp_mq_poll,&mtq[n]);
		
		CPU_ZERO(&target_cpu_set);
		CPU_SET(mtq[n].cpu,&target_cpu_set);
		pthread_setaffinity_np(sock_tid[n],sizeof(cpu_set_t),&target_cpu_set);
	}

	for(n=0;n<nnts;n++){
		pthread_join(sock_tid[n],NULL);
	}
}
*/
void nettlp_stop_cb(void)
{
	stop_flag = 1;
}


/*
 * Messaging API for NetTLP driver.
 */

static int nettlp_msg_socket(struct in_addr addr)
{
	int fd, ret;
	struct sockaddr_in saddr;

	fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (fd < 0)
		return fd;

	memset(&saddr, 0, sizeof(saddr));
	saddr.sin_family = AF_INET;
	saddr.sin_addr = addr;
	saddr.sin_port = htons(NETTLP_MSG_PORT);
	ret = connect(fd, (struct sockaddr *)&saddr, sizeof(saddr));
	if (ret < 0)
		return ret;

	return fd;
}

uintptr_t nettlp_msg_get_bar4_start(struct in_addr addr)
{
	int sock, req, ret = 0;
	uintptr_t bar4_addr = 0;
	struct pollfd x[1];

	sock = nettlp_msg_socket(addr);
	if (sock < 1)
		return 0;

	/* send GET_BAR4 request */
	req = NETTLP_MSG_GET_BAR4_ADDR;
	ret = write(sock, &req, sizeof(req));

	/* recv response with timeout */
	x[0].fd = sock;
	x[0].events = POLLIN;

	ret = poll(x, 1, LIBTLP_CPL_TIMEOUT);
	if (ret == 0) {
		errno = ETIME;
		goto err_out;
	}

	ret = read(sock, &bar4_addr, sizeof(bar4_addr));
	if (ret < 0)
		goto err_out;

	close(sock);
	return bar4_addr;

err_out:
	close(sock);
	return 0;
}

uint16_t nettlp_msg_get_dev_id(struct in_addr addr)
{
	int sock, req, ret = 0;
	uint16_t devid;
	struct pollfd x[1];

	sock = nettlp_msg_socket(addr);
	if (sock < 1)
		return 0;

	/* send GET_BAR4 request */
	req = NETTLP_MSG_GET_DEV_ID;
	ret = write(sock, &req, sizeof(req));

	/* recv response with timeout */
	x[0].fd = sock;
	x[0].events = POLLIN;

	ret = poll(x, 1, LIBTLP_CPL_TIMEOUT);
	if (ret == 0) {
		errno = ETIME;
		goto err_out;
	}

	ret = read(sock, &devid, sizeof(devid));
	if (ret < 0)
		goto err_out;

	close(sock);
	return devid;

err_out:
	close(sock);
	return 0;
}


int nettlp_msg_get_msix_table(struct in_addr addr, struct nettlp_msix *msix,
			      int msix_count)
{
	int sock, req, ret = 0;
	struct pollfd x[1];

	sock = nettlp_msg_socket(addr);
	if (sock < 1)
		return 0;

	/* send GET_BAR4 request */
	req = NETTLP_MSG_GET_MSIX_TABLE;
	ret = write(sock, &req, sizeof(req));

	/* recv response with timeout */
	x[0].fd = sock;
	x[0].events = POLLIN;

	ret = poll(x, 1, LIBTLP_CPL_TIMEOUT);
	if (ret == 0) {
		errno = ETIME;
		goto err_out;
	}

	ret = read(sock, msix, sizeof(struct nettlp_msix) * msix_count);
	if (ret < 0)
		goto err_out;

	close(sock);
	return 0;

err_out:
	close(sock);
	return -1;
}


/*
 * PCIe Configuration API
 *
 * see https://scrapbox.io/sora/NetTLP_packet
 */

struct nettlp_pcie_cfg_pkt {

#if __BYTE_ORDER == __LITTLE_ENDIAN
	uint16_t dwaddrh : 2;
	uint8_t mask : 4;
	uint8_t cmd: 2;
#elif __BYTE_ORDER == __BIG_ENDIAN
	uint8_t cmd: 2;
	uint8_t mask : 4;
	uint16_t dwaddrh : 2;

#endif
	uint8_t dwaddrl;

	uint32_t data;

} __attribute__((packed));

#define NETTLP_PCIE_CFG_CMD_READ	0x0
#define NETTLP_PCIE_CFG_CMD_WRITE	0x1

#define NETTLP_PCIE_CFG_TIMEOUT		1000	/* msec */

int nettlp_pcie_cfg_init(struct nettlp_pcie_cfg *ntpc)
{
	int fd;

	fd = nettlp_create_udp_socket(ntpc->remote_addr, NETTLP_PCIE_CFG_PORT,
				      ntpc->local_addr, NETTLP_PCIE_CFG_PORT);
	if (fd < 0)
		return fd;

	ntpc->sockfd = fd;
	return 0;
}

static void pcie_cfg_set_dwaddr(struct nettlp_pcie_cfg_pkt *pkt,
				uint16_t dwaddr)
{
	pkt->dwaddrh = ((dwaddr & 0x0300)) >> 8;
	pkt->dwaddrl = (dwaddr & 0x00FF);
}

static int pcie_cfg_read_dw(struct nettlp_pcie_cfg *ntpc, uint16_t dwaddr,
			    uint8_t mask, uint32_t *data)
{
	int ret;
	struct nettlp_pcie_cfg_pkt pkt;
	struct pollfd x[1];

	/* send READ command */
	pkt.cmd = NETTLP_PCIE_CFG_CMD_READ;
	pkt.mask = mask;
	pcie_cfg_set_dwaddr(&pkt, dwaddr);
	pkt.data = 0;
	ret = write(ntpc->sockfd, &pkt, sizeof(pkt));
	if (ret < 0)
		return ret;

	/* receive READ command reply */
	x[0].fd = ntpc->sockfd;
	x[0].events = POLLIN;

	ret = poll(x, 1, NETTLP_PCIE_CFG_TIMEOUT);
	if (ret < 0)
		return ret;
	if (ret == 0) {
		errno = ETIME;
		return -1;
	}
	if (!(x[0].revents & POLLIN)) {
		errno = ENODATA;
		return -1;
	}

	ret = read(ntpc->sockfd, &pkt, sizeof(pkt));
	if (ret < 0)
		return ret;

	*data = be32toh(pkt.data);

	return 0;
}

static int pcie_cfg_write_dw(struct nettlp_pcie_cfg *ntpc, uint16_t dwaddr,
			     uint8_t mask, uint32_t data)
{
	int ret;
	struct nettlp_pcie_cfg_pkt pkt;

	pkt.cmd = NETTLP_PCIE_CFG_CMD_WRITE;
	pkt.mask = mask;
	pcie_cfg_set_dwaddr(&pkt, dwaddr);
	pkt.data = htobe32(data);
	ret = write(ntpc->sockfd, &pkt, sizeof(pkt));
	if (ret < 0)
		return ret;

	return 0;
}

ssize_t nettlp_pcie_cfg_read(struct nettlp_pcie_cfg *ntpc, uint16_t addr,
			     void *buf, size_t count)
{
	int ret;
	uint16_t dwaddr;
	uint8_t mask;
	uint32_t data;
	uint8_t *ptr;

	int len, read = 0;
	uint16_t start_dwaddr, end_dwaddr;
	int fstpad;	/* unnecessary bytes in first DWORD */
	int lstpad;	/* unnecessary bytes in last DWORD */

	fstpad = addr & 0x0003;
	lstpad = 4 - ((addr + count) & 0x0003);

	start_dwaddr = addr >> 2;
	end_dwaddr = (addr + count) >> 2;
	/* A cornor case: If (addr + count) is a multple of 4, lastpad
	 * becomes 4, which means no need to read the end dword.
	 * Thus, decrement end_dwaddr and set lstpad 0.
	 */
	if (lstpad == 4) {
		lstpad = 0;
		end_dwaddr--;
	}

	for (dwaddr = start_dwaddr; dwaddr <= end_dwaddr; dwaddr++) {

		mask = 0xF;
		if (dwaddr == start_dwaddr && fstpad) {
			mask &= ((0x0F << fstpad) & 0x0F);
		}
		if (dwaddr == end_dwaddr && lstpad) {
			mask &= ((0x0F >> lstpad) & 0x0F);
		}

		ret = pcie_cfg_read_dw(ntpc, dwaddr, mask, &data);
		if (ret < 0)
			return ret;

		len = 4;
		ptr = (uint8_t *)&data;
		if (dwaddr == start_dwaddr && fstpad) {
			len -= fstpad;
			ptr += fstpad;
		}
		if (dwaddr == end_dwaddr && lstpad) {
			len -= lstpad;
		}

		memcpy(buf, ptr, len);
		buf += len;
		read += len;
	}

	return read;
}

ssize_t nettlp_pcie_cfg_write(struct nettlp_pcie_cfg *ntpc, uint16_t addr,
			      void *buf, size_t count)
{
	int ret;
	uint16_t dwaddr;
	uint8_t mask;
	uint32_t data;
	uint8_t *ptr;

	int len, written = 0;
	uint16_t start_dwaddr, end_dwaddr;
	int fstpad;	/* unnecessary bytes in first DWORD */
	int lstpad;	/* unnecessary bytes in last DWORD */

	fstpad = addr & 0x0003;
	lstpad = 4 - ((addr + count) & 0x0003);

	start_dwaddr = addr >> 2;
	end_dwaddr = (addr + count) >> 2;
	if (lstpad == 4) {
		lstpad = 0;
		end_dwaddr--;
	}

	for (dwaddr = start_dwaddr; dwaddr <= end_dwaddr; dwaddr++) {
		len = 4;
		mask = 0xF;
		data = 0;
		ptr = (uint8_t *)&data;
		if (dwaddr == start_dwaddr && fstpad) {
			mask &= ((0x0F << fstpad) & 0x0F);
			len -= fstpad;
			ptr += fstpad;
		}
		if (dwaddr == end_dwaddr && lstpad) {
			mask &= ((0x0F >> lstpad) & 0x0F);
			len -= lstpad;
		}

		memcpy(ptr, buf, len);

		ret = pcie_cfg_write_dw(ntpc, dwaddr, mask, data);
		if (ret < 0)
			return ret;

		buf += len;
		written += len;
	}

	return written;
}
