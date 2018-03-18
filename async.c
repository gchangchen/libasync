
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netdb.h>
#include <fcntl.h>
#include <errno.h>
#include <arpa/inet.h>
#include <assert.h>

#include "async.h"

#ifdef HAVE_LIBEV
#include <ev.h>
#else
#define EV_STANDALONE 1
#define EV_FEATURES 0
#define EV_MULTIPLICITY 1
#define EV_USE_EPOLL 1
//#define EV_API_STATIC 1
#include "libev/ev.c"
#endif //HAVE_LIBEV

#define HAVE_SETJMP_H 1
#define HAVE_SIGALTSTACK 1
#define CORO_STACKALLOC 0
#include "libcoro/coro.c"
#define STACK_SIZE (1024*1024)
typedef void (*coroutine_func)(void *ud);
struct schedule {
	char stack[STACK_SIZE];
	struct coro_context main_ctx;
	struct coroutine * volatile running;
	struct coroutine * volatile ready_co;
};
struct coroutine {
	struct coroutine *next;
	struct coro_context ctx;
	coroutine_func func;
	void *ud;
	ptrdiff_t cap;
	ptrdiff_t size;
	char *volatile stack;
	int data;
};
static struct schedule *S= NULL;
static void mainfunc(struct coroutine * volatile co){
	assert(co);
	S->running = co;
	co->func(co->ud);
	free(co->stack);
	co->stack = NULL;
	S->running = NULL;
	coro_transfer (& co->ctx, &S->main_ctx);
}
static struct coroutine *coroutine_new(coroutine_func func, void *ud) {
	if(S == NULL){
		S = malloc(sizeof(*S));
		if( S == NULL)return NULL;
		S->running = NULL;
		S->ready_co = NULL;
	}
	struct coroutine *co = malloc(sizeof(*co));
	if(co == NULL)return NULL;
	co->func = func;
	co->ud = ud;
	co->cap = 8 * 1024;
	co->size = 0;
	co->stack = malloc(co->cap);
	if(co->stack) return co;
	free(co);
	return NULL;
}
static void coroutine_resume(struct coroutine *co){
	assert(S->running == NULL);
	assert(co);
	if(co->size){
		//恢复协程的栈。
		memcpy(S->stack + STACK_SIZE - co->size, co->stack, co->size);
	}else{
		coro_create (& co->ctx, (void (*)(void*))mainfunc, (void *)co, S->stack, STACK_SIZE);
	}

	S->running = co;
	//printf("transfer to %p\n", co);
	coro_transfer(& S->main_ctx, &co->ctx);
	S->running = NULL;
	if(co->stack == NULL){
		coro_destroy (& co->ctx);
		free(co);
	}else{
		//保存协程的栈内容，在这里保存是为了防止丢失切换过程中的栈内容。
		memcpy(co->stack, S->stack + STACK_SIZE - co->size, co->size);
	}
}
static void coroutine_yield(void) {
	struct coroutine *co = S->running;
	assert(co);
	assert((char *)&co > S->stack);
	co->size = S->stack + STACK_SIZE - (char*)&co + sizeof(char*) * 16;
	if(co->cap < co->size){
		free(co->stack);
		co->cap = co->size;
		co->stack = malloc(co->cap);
		assert(co->stack);
	}
	//栈烤贝放到切换后，在coroutine_resume中回到主协程后。避免丢失切换中栈的内容。
	//memcpy(co->stack, S->stack + STACK_SIZE - co->size, co->size);
	S->running = NULL;
	coro_transfer(&co->ctx , &S->main_ctx);
}
static struct coroutine *coroutine_running(void) {
	return S->running;
}

#define BUF_SIZE	8192

#define DNS_HOST  0x01
#define DNS_HOST_V6  0x1c
#define DNS_SVR "8.8.8.8"
static char dns_addr_buf[sizeof(struct sockaddr_in6)];
static struct sockaddr *const dns_addr = (struct sockaddr*)dns_addr_buf;

static struct ev_loop *loop;
int async_init(const char *name_server){
	loop = EV_DEFAULT;
	S = malloc(sizeof(*S));
	if( S == NULL)return -1;
	S->running = NULL;
	S->ready_co = NULL;

	if(name_server == NULL)name_server = DNS_SVR;
	char buf[512];
	strcpy(buf, name_server);
	char *p = strchr(buf, ' ');
	if(p){
		*p = '\0';
		p++;
	}
	char *host = buf;
	p = strchr(buf, '#');
	if(p){
		*p = '\0';
		p++;
	}else{
		p = "53";
	}

	struct addrinfo *answer, hint;
	memset(&hint, 0, sizeof(hint));
	hint.ai_family = AF_UNSPEC;
	hint.ai_socktype = SOCK_DGRAM;
	int ret = getaddrinfo(host, p, &hint, &answer);
	if (ret != 0 || answer == NULL) {
		return -1;
	}
	memcpy(dns_addr, answer->ai_addr, answer->ai_addrlen);
	freeaddrinfo(answer);
	return 0;
}
void async_destroy(void){
	if(S){
		free(S);
		S = NULL;
	}
	//TODO free coro_queue;
}
void async_run(){
	int need_continue = 1;
	while(S->ready_co || need_continue){
		while(S->ready_co){
			struct coroutine *co = S->ready_co;
			S->ready_co = co->next;
			coroutine_resume(co);
		}
		need_continue = ev_run(EV_A_ EVRUN_ONCE);
	}
	return;
}

struct coroutine *async_start(void (*fn)(void *), void *arg){
	struct coroutine *co = coroutine_new(fn, arg);
	if(co){
		co->next = S->ready_co;
		S->ready_co = co;
	}
	return co;
}
static void  _asyn_wait_wto(int revents, void *arg){
	struct coroutine *co = arg;
	co->data = revents;
	co->next = S->ready_co;
	S->ready_co = co;
}

int async_wait_wto(int fd, int events, ev_tstamp timeout){
	struct coroutine *co = coroutine_running();
	assert(co);
	ev_once(EV_A_ fd, events, timeout, _asyn_wait_wto, co);
	coroutine_yield();
	if( co->data & EV_TIMER){
		errno = ETIMEDOUT;
		return -1;
	}
	return 0;
}

int async_accept_wto(int fd, struct sockaddr *addr, socklen_t *addrlen, ev_tstamp timeout){
	setnonblocking(fd);
	async_wait_wto(fd, EV_READ, timeout);
	int newfd = accept(fd, addr, addrlen);
	if (newfd != -1) {
		setnonblocking(newfd);
	}
	return newfd;
}

void _async_accept_handle(void *arg){
	struct coroutine *co = coroutine_running();
	int fd = co->data;
	void (*fn)(void *) = arg;
	int newfd;
	while(1){
		newfd = async_accept_wto(fd, NULL, NULL, -1);
		if(newfd == -1 && errno != EAGAIN && errno != EINTR)break;
		if(newfd != -1){
			async_start(fn, NULL + newfd);
		}
	}
	//assert(0);
}
struct coroutine *async_accept_handle(int fd, void (*fn)(int fd)){
	struct coroutine *co = async_start(_async_accept_handle, (void *)fn);
	if(co) co->data = fd;
	return co;
}

int async_connect_wto(int fd, const struct sockaddr *addr, socklen_t addrlen, ev_tstamp timeout){
	setnonblocking(fd);
	int ret = connect(fd, addr, addrlen);
	if(ret == 0)return ret;
	if(ret == -1 && errno != EINPROGRESS)return -1;

	if(async_wait_wto(fd, EV_WRITE, timeout) == -1)return -1;

	addrlen = sizeof(ret);
	if(-1 == getsockopt(fd, SOL_SOCKET, SO_ERROR, (void *)&ret, &addrlen) || 0 != ret ) {
		return -1;
	}
	return 0;
}
int async_getipbyname(const char *host, unsigned short sa_family, void *result, size_t result_length){
	if(sa_family != AF_INET6)sa_family = AF_INET;
	int max_count = result_length / (sa_family == AF_INET ? sizeof(struct in_addr) : sizeof(struct in6_addr));
	if(host == NULL || result == NULL || max_count <= 0)return -1;
	unsigned char flag = *(unsigned char*)result;
	if(flag)flag = 1;
	memset(result, 0, result_length);

	if(inet_pton(sa_family, host, result) == 1){
		return 1;
	}

	size_t host_len = strlen(host);
	if(host_len < 3){
		return -1;
	}
	unsigned char buf[513];
	memcpy(buf, "\xff\x00\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00", 12); 
	unsigned char *p = buf + 12;
	for(int i = 0; i<=host_len; i++){
		if(*(host+i) == '.' || i == host_len){
			*p = (unsigned char)(i -(p - buf -12));
			p += *p + 1;
		}else{
			buf[13 + i] = *(host+i);
		}
	}
	memcpy(buf+12+1+host_len, "\x00\x00\x01\x00\x01", 5);
	if(sa_family == AF_INET6){
		buf[host_len+15] = 0x1c;
	}

	int ip_count = 0;

	int dns_fd = socket(dns_addr->sa_family, SOCK_DGRAM, 0);
	if(dns_fd < 0){
		return -1;
	}
	setnonblocking(dns_fd);
	
	ssize_t n = 0;
	for(int i=0; i<2; i++){
		n = async_sendto(dns_fd, buf, host_len + 18, 0, dns_addr, dns_addr->sa_family == AF_INET
				? sizeof(struct sockaddr_in): sizeof(struct sockaddr_in6));
		if(n != host_len + 18)continue;
		n = async_recvfrom_wto(dns_fd, buf, sizeof(buf), 0, NULL, NULL, 0.4);
		if(n > 0)break;
	}
	if(n > 18){
		buf[n] = '\0';
		int querys = ntohs(*((unsigned short*)(buf+4)));
		int answers = ntohs(*((unsigned short*)(buf+6)));
		const char *p = buf + 12;
		for(int i= 0 ; i < querys ; i ++){
			if(*p & 0xc0)p+=6;
			else p += strlen(p)+5;
			if((unsigned char*)p > buf + n)goto end;
		}
		for(int i = 0 ; i < answers ; i ++){
			if((unsigned char*)p > buf + n)break;
			if(*p & 0xc0)p+=2;
			else p += strlen(p)+1;
			if((unsigned char*)p > buf + n - 10)break;
			short type = ntohs(*((unsigned short*)p));
			short datalen = ntohs(*((unsigned short*)(p+8)));
			if((sa_family == AF_INET6 && type == DNS_HOST_V6 && datalen == 16) ||
					(sa_family == AF_INET && type == DNS_HOST && datalen == 4)){
				memcpy(result + datalen * ip_count, p+10, datalen);
				ip_count++;
				if(ip_count >= max_count)break;
			}
			p += datalen + 10;
		}
	}

end:
	if(dns_fd >= 0){
		close(dns_fd);
		dns_fd = -1;
	}
	return ip_count;
}

//flag = IPV4_FIRST(0), IPV6_FIRST(1), IPV4_ONLY(2), IPV6_ONLY(3)...
int async_connect_host_wto(const char *host, unsigned short port, ev_tstamp timeout, int flag){
	if(host == NULL || port == 0)return -1;

	int fd = -1;
	int ip_count;

	if(flag == 1 || flag == 3){
		struct in6_addr v6_addr[16]={0};
		for(int j=0; j<2; j++){
			ip_count = async_getipbyname(host, AF_INET6, v6_addr, sizeof(v6_addr));
			for(int i=0; i<ip_count; i++){
				struct sockaddr_in6 addr6 = {0};
				addr6.sin6_family = AF_INET6;
				addr6.sin6_port = htons(port);
				addr6.sin6_addr = v6_addr[i];
				fd = socket(AF_INET6, SOCK_STREAM, 0);
				int ret = async_connect_wto(fd, (struct sockaddr *)&addr6, sizeof(addr6), timeout);
				if(ret < 0){
					close(fd);
					fd = -2;
				}else{
					return fd;
				}
			}
			memset(&v6_addr, 0x01, 1);
		}
		if(flag == 1){
			return async_connect_host_wto(host, port, timeout, 2);
		}
	}
	if(flag == 0 || flag == 2){
		struct in_addr v4_addr[16]={0};
		for(int j=0; j<2; j++){
			ip_count = async_getipbyname(host, AF_INET, v4_addr, sizeof(v4_addr));
			for(int i=0; i<ip_count; i++){
				struct sockaddr_in addr = {0};
				addr.sin_family = AF_INET;
				addr.sin_port = htons(port);
				addr.sin_addr = v4_addr[i];
				fd = socket(AF_INET, SOCK_STREAM, 0);
				int ret = async_connect_wto(fd, (struct sockaddr *)&addr, sizeof(addr), timeout);
				if(ret < 0){
					close(fd);
					fd = -2;
				}else{
					return fd;
				}
			}
			memset(&v4_addr, 0x01, 1);
		}
		if(flag == 0){
			return async_connect_host_wto(host, port, timeout, 3);
		}
	}
	return fd;
}

ssize_t async_read_wto(int fd, void *buf, size_t count, ev_tstamp timeout){
	assert(count > 0);
	ssize_t ret = -1;
	do{
		if(async_wait_wto(fd, EV_READ, timeout) == -1)break;
		ret = read(fd, buf, count);
	}while(ret == -1 && errno == EINPROGRESS);
	return ret;
}
ssize_t async_read_all_wto(int fd, void *buf, size_t count, ev_tstamp timeout){
	ssize_t ret = 0;
	while(ret < count){
		int n = async_read_wto(fd, buf + ret, count - ret, timeout);
		if(n <=0)break;
		ret += n;
	}
	return ret;
}

ssize_t async_write_wto(int fd, const void *buf, size_t count, ev_tstamp timeout){
	assert(count > 0);
	ssize_t ret = -1;
	do{
		if(async_wait_wto(fd, EV_WRITE, timeout) == -1)break;
		ret = write(fd, buf, count);
	}while(ret == -1 && errno == EINPROGRESS);
	return ret;
}
ssize_t async_write_all_wto(int fd, const void *buf, size_t count, ev_tstamp timeout){
	ssize_t ret = 0;
	while(ret < count){
		int n = async_write_wto(fd, buf + ret, count - ret, timeout);
		if(n <=0)break;
		ret += n;
	}
	return ret;
}

ssize_t async_sendto_wto(int fd, const void *buf, size_t len, int flags, const
		struct sockaddr *dest_addr, socklen_t addrlen, ev_tstamp timeout){
	if(async_wait_wto(fd, EV_WRITE, timeout) != 0)return -1;
	return sendto(fd, buf, len, flags, dest_addr, addrlen);
}
ssize_t async_recvfrom_wto(int fd, void *buf, size_t len, int flags,
		struct sockaddr *src_addr, socklen_t *addrlen, ev_tstamp timeout){
	if(async_wait_wto(fd, EV_READ, timeout) != 0)return -1;
	return recvfrom(fd, buf, len, flags, src_addr, addrlen);
}

int create_server(const char *addr, unsigned short port, int type){
	struct addrinfo hints;
	struct addrinfo *result, *rp;
	int s, listen_sock;

	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = type;
	hints.ai_flags = AI_PASSIVE;

	char buf[8];
	sprintf(buf, "%d", port);
	s = getaddrinfo(addr, buf, &hints, &result);
	if (s != 0) {
		return -1;
	}

	for (rp = result; rp != NULL; rp = rp->ai_next) {
		listen_sock = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
		if (listen_sock == -1) {
			continue;
		}

		int opt = 1;
		setsockopt(listen_sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

		s = bind(listen_sock, rp->ai_addr, rp->ai_addrlen);
		if (s == 0) {
			break;
		} else {
			close(listen_sock);
			listen_sock = -1;
		}
	}

	if (rp == NULL) {
		return -1;
	}

	freeaddrinfo(result);
	if(type == SOCK_STREAM && listen_sock >= 0){
		s = listen(listen_sock, SOMAXCONN);
		if(s == -1){
			close(listen_sock);
			listen_sock = -1;
		}
	}
	return listen_sock;
}
int setnonblocking(int fd){
	int flags;
	if (-1 == (flags = fcntl(fd, F_GETFL, 0))) {
		flags = 0;
	}
	return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

size_t async_cat(int src, int dst, ssize_t len, ev_tstamp timeout){
	size_t ret = 0;
	char *buf = malloc(BUF_SIZE);
	if(buf == NULL)return 0;
	while(len < 0 || ret < len){
		ssize_t n = async_read_wto(src, buf, len -ret > BUF_SIZE ? BUF_SIZE : len-ret, timeout);
		if(n <= 0)break;
		ssize_t m = async_write_all_wto(dst, buf, n, timeout);
		if(m > 0)ret += m;
		if(m <= 0 || m != n)break;
	}
	free(buf);
	return ret;
}

