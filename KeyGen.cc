#include<iostream>
#include<sys/socket.h>
#include<stdlib.h>
#include<string.h>
#include<arpa/inet.h>
#include<netinet/in.h>
#include<pthread.h>
using namespace std;

struct pthread_socket
{
	int socket_d;
};

int sign_Verify(){
	return 0;
}

static void* thread_keygenerate(void *arg)
{
	
}
//listen a port, accepted register procedure in muti-thread, set max-connections such as 20.
int sock_init(int port = 11111){
    int listen_sock;
	int listen_max=20;//max listen number
	struct sockaddr_in sockaddr; //定义IP地址结构
	int on = 1;
	listen_sock = socket(AF_INET, SOCK_STREAM, 0); //初始化socket
	if (listen_sock == -1)
	{
		printf("socket create error \n");
		return ;
	}
	if (setsockopt(listen_sock, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) == -1) //设置ip地址可重用
	{
		printf("setsockopt error \n");
		return ;
	}
	sockaddr.sin_port = htons(port);
	sockaddr.sin_family = AF_INET;    //设置结构类型为TCP/IP
	sockaddr.sin_addr.s_addr = htonl(INADDR_ANY);    //服务端是等待别人来连，不需要找谁的ip
	if (bind(listen_sock, (struct sockaddr *) &sockaddr, sizeof(sockaddr)) == -1)
	{
		printf("bind error \n");
		return ;
	}

	if (listen(listen_sock, 20) == -1) //     服务端开始监听
	{
		printf("listen error \n");
		return ;
	}
	printf("init successful!, listen begin \n");
	pthread_t KenGen;
	while (1)
    	{
			struct pthread_socket ps;
			int accept_st;
    		struct sockaddr_in accept_sockaddr; //定义accept IP地址结构
    		socklen_t addrlen = sizeof(accept_sockaddr);
    		memset(&accept_sockaddr, 0, addrlen);
			accept_st = accept(listen_sock, (struct sockaddr*) &accept_sockaddr,&addrlen);
			if (accept_st == -1)
    		{
        		printf("accept error");
        		continue;
    		}
			ps.socket_d = accept_st;
			if (pthread_create(&KenGen, NULL, thread_keygenerate, &ps) != 0)//创建接收信息线程
        	{
            		printf("create thread error to sock %d \n", accept_st);
        	}
		}

}