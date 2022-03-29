// date: 2022.3.19
// author: chendaole
// email: 1174250185@qq.com

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include "tiny_gin.h"
#include "router_myblog.h"

#define PORT 8080
#define BACKLOG 5000

void print_char(char *in, size_t in_n) {
    for(size_t i = 0; i < in_n; i ++) {
        printf("%c", in[i]);
    }
    printf("\n");
}

int socket_fd;

void signal_exit(int signal) {
    close(socket_fd);
    printf("Bye Bye!!!\n");
    exit(1);
}

int main() {
    signal(SIGINT, signal_exit);
    signal(SIGTERM, signal_exit);

    struct sockaddr_in my_addr;
    struct sockaddr_in their_addr;
    tiny_gin_engine *s_engine;
    int on = 1;

    socket_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (socket_fd == -1) {
        printf("open local port failed = %d", errno);
        return -1;
    }

    my_addr.sin_family = AF_INET;
    my_addr.sin_port = htons(PORT);
    my_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    bzero(&my_addr.sin_zero, 8);

    setsockopt(socket_fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
    if (bind(socket_fd, (struct sockaddr*)&my_addr, sizeof(struct sockaddr)) < 0) {
        printf("bind my_addr failed = %d", errno);
        return -1;
    }

    if(listen(socket_fd, BACKLOG) == -1) {
        printf("listen socket failed = %d", errno);
        return -1;
    }

    printf("Hi MyBlog\n");
    printf("start server, port=%d\n", PORT);

    // 初始化路由
    s_engine = new_router_engine_default();
    init_router_myblog(s_engine->s_router_group);

    // socket loop
    while (1) {
        uint socketaddr_in_n = sizeof(struct sockaddr_in);
        int receive_fd = accept(socket_fd, (struct sockaddr *)&their_addr, &socketaddr_in_n);
        if (receive_fd == -1) {
            printf("receive socket failed = %d\n", errno);
        } else {
            tiny_gin_run(receive_fd, s_engine);
            //send(receive_fd, "Hi My Blog\n", 11, 0);
            close(receive_fd);
        }
    }

    return 0;
}
