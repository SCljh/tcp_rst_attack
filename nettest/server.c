#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#define BUFF_SIZE 140

void main()
{
    int server_sockfd;

    server_sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (server_sockfd == -1) {
        perror("Create socket error");
        exit(-1);
    }

    struct sockaddr_in server_addr;

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(2807);
    server_addr.sin_addr.s_addr = htonl(INADDR_ANY);

    if (bind(server_sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) == -1) {
        perror("Socket bind error");
        exit(-1);
    }

    if (listen(server_sockfd, 5) == -1) {
        perror("Socket listen error");
        exit(-1);
    }

    int client_sockfd, client_addr_len;
    struct sockaddr_in client_addr;

    client_addr_len = sizeof(client_addr);
    client_sockfd = accept(server_sockfd, (struct sockaddr *)&client_addr, &client_addr_len);

    int n;
    char buff[BUFF_SIZE];

    do {
        n = recv(client_sockfd, buff, BUFF_SIZE - 1, 0);
        if (n > 0) {
            buff[n] = '\0';
            printf("recv: %d: %s\n", n, buff);
        } else if (n == 0) {
            printf("Connection closed by foreign host.\n");
            break;
        } else if (n == -1) {
            perror("Receive data error");
            exit(-1);
        }
    } while (strncasecmp(buff, "exit", 4) != 0);

    close(client_sockfd);
    close(server_sockfd);
}
