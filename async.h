
#ifndef _ASYNC_H
#define _ASYNC_H

#include <sys/socket.h>

#ifdef __cplusplus
extern "C" {
#endif

	struct coroutine;

	int async_init(const char *name_server);
	void async_destroy(void);
	void async_run(void);

	struct coroutine *async_start(void (*fn)(void *arg), void *arg);
	int async_wait_wto(int fd, int events, double timeout);
#define async_sleep(timeout) async_wait_wto(-1,0,(timeout))

	int async_accept_wto(int fd, struct sockaddr *addr, socklen_t *addrlen, double timeout);
#define async_accept(fd,addr,addrlen) async_accept_wto((fd),(addr),(addrlen),-1)
	struct coroutine *async_accept_handle(int fd, void (*fn)(int fd));

	int async_getipbyname(const char *host, unsigned short sa_family, void *result, size_t result_length);
	int async_connect_wto(int fd, const struct sockaddr *addr, socklen_t addrlen, double timeout);
	int async_connect_host_wto(const char *host, unsigned short port, double timeout, int ipv6_first);
#define async_connect(fd,addr,addrlen) async_connect_wto((fd), (addr), (addrlen), -1)

	ssize_t async_read_wto(int fd, void *buf, size_t count, double timeout);
	ssize_t async_read_all_wto(int fd, void *buf, size_t count, double timeout);
#define async_read(fd,buf,count) async_read_wto((fd),(buf),(count),-1)
#define async_read_all(fd,buf,count) async_read_all_wto((fd),(buf),(count),-1)

	ssize_t async_write_wto(int fd, const void *buf, size_t count, double timeout);
	ssize_t async_write_all_wto(int fd, const void *buf, size_t count, double timeout);
#define async_write(fd,buf,count) async_write_wto((fd),(buf),(count),-1)
#define async_write_all(fd,buf,count) async_write_all_wto((fd),(buf),(count),-1)

	ssize_t async_sendto_wto(int fd, const void *buf, size_t len, int flags,
			const struct sockaddr *dest_addr, socklen_t addrlen, double timeout);
#define async_sendto(fd,buf,len,flags,dest_addr,addrlen) async_sendto_wto((fd),(buf),(len),(flags),(dest_addr),(addrlen),-1)
	ssize_t async_recvfrom_wto(int fd, void *buf, size_t len, int flags,
			struct sockaddr *src_addr, socklen_t *addrlen, double timeout);
#define async_recvfrom(fd,buf,len,flags,src_addr,addrlen) async_recvfrom_wto((fd),(buf),(len),(flags),(src_addr),(addrlen),-1)

	size_t async_cat(int src, int dst, ssize_t len, double timeout);

	int create_server(const char *addr, unsigned short port, int type);
#define create_tcp_server(addr, port) create_server((addr),(port), SOCK_STREAM)
#define create_udp_server(addr, port) create_server((addr),(port), SOCK_DGRAM)
	int setnonblocking(int fd);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif
