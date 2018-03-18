#include "async.h"

#include<stdio.h>
#include<string.h>
#include<unistd.h>

//echo server handle.fd is the client fd.
void echo_handle(int fd)
{
	async_cat(fd, fd, -1, -1);
	close(fd);
}

//echo client. arg is pass by main, not used.
void echo_client(void *arg)
{
	if(arg)async_sleep(1);

	int fd = async_connect_host_wto("127.0.0.1", 4000, 3, 0);
	if(fd < 0){
		perror("async_connect_host_wto error");
		goto end;
	}

	char buf[1024];
	for(int i = 0; i<5; i++){
		int len = sprintf(buf, "cliend:%d %d\n", fd, i);
		if(len != async_write_all(fd, buf, len))break;
		if(len != async_read_all(fd, buf, len))break;
		buf[len] = '\0';
		printf("recv:%s\n", buf); 
		async_sleep(2);
	}

end:
	if(fd >= 0)close(fd);
}

//http client. arg is pass by main, not used.
void http_client(void *arg)
{
	async_sleep(5);
	int fd = async_connect_host_wto("github.com", 80, 3, 0);
	if(fd < 0){
		perror("async_connect_host_wto to github error");
		goto end;
	}
	const char *req = "GET / HTTP/1.0\r\nHost:github.com\r\n\r\n";
	int len = strlen(req);
	if(len != async_write_all(fd, req, len)){
		perror("write to github.com error!");
		goto end;
	}
	async_cat(fd, 1, -1, 10);

end:
	if(fd >= 0)close(fd);
}


int main(int argc, char *argv[])
{
	if(async_init("8.8.8.8"))return -1;

	//create echo server.
	int s = create_tcp_server("127.0.0.1", 4000);
	if(s < 0)return -1;
	struct coroutine *co = async_accept_handle(s, echo_handle);
	if(co == NULL)goto end;

	//start a coroutine for echo client.
	co = async_start(echo_client, NULL);
	if(co == NULL){
		printf("async_start echo_client error!");
		goto end;
	}
	//start another coroutine for echo client.
	co = async_start(echo_client, NULL + 2);
	if(co == NULL){
		printf("async_start another echo_client error!");
		goto end;
	}

	//start a coroutine for http client.
	co = async_start(http_client, NULL);
	if(co == NULL){
		printf("async_start http_client error!");
		goto end;
	}

	async_run();
	async_destroy();

end:
	if(s>=0)close(s);
	return 0;
}
