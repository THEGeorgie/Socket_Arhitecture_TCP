#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/wait.h>
#include <signal.h>

#define PORT "3490"  // the port users will be connecting to
#define BUFFER_SIZE 100
#define BACKLOG 10   // how many pending connections queue will hold

void sigchld_handler(int s) {
    (void) s; // Quiet unused variable warning
    int saved_errno = errno;
    while (waitpid(-1, NULL, WNOHANG) > 0);
    errno = saved_errno;
}

// Get IPv4 or IPv6 address
void *get_in_addr(struct sockaddr *sa) {
    if (sa->sa_family == AF_INET) {
        return &(((struct sockaddr_in *) sa)->sin_addr);
    }
    return &(((struct sockaddr_in6 *) sa)->sin6_addr);
}

int main(void) {
    int sockfd, *new_fd;
    int *sockfdStored[BACKLOG] = {0}; // Array to store client sockets
    struct addrinfo hints, *servinfo, *p;
    struct sockaddr_storage their_addr;
    socklen_t sin_size;
    struct sigaction sa;
    int yes = 1;
    char s[INET6_ADDRSTRLEN];
    int rv;
    // Buffer for client response
    char buffer[BUFFER_SIZE];
    int num_bytes;
    int *countClients = malloc(sizeof(int));
    *countClients = 0;

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE; // Use my IP

    if ((rv = getaddrinfo(NULL, PORT, &hints, &servinfo)) != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
        return 1;
    }

    // Loop through results and bind to the first available
    for (p = servinfo; p != NULL; p = p->ai_next) {
        if ((sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1) {
            perror("server: socket");
            continue;
        }

        if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == -1) {
            perror("setsockopt");
            exit(1);
        }

        if (bind(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
            close(sockfd);
            perror("server: bind");
            continue;
        }
        break;
    }

    freeaddrinfo(servinfo);

    if (p == NULL) {
        fprintf(stderr, "server: failed to bind\n");
        exit(1);
    }

    if (listen(sockfd, BACKLOG) == -1) {
        perror("listen");
        exit(1);
    }

    sa.sa_handler = sigchld_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    if (sigaction(SIGCHLD, &sa, NULL) == -1) {
        perror("sigaction");
        exit(1);
    }

    printf("server: waiting for connections...\n");
    while (1) {
        sin_size = sizeof their_addr;
        *new_fd = accept(sockfd, (struct sockaddr *) &their_addr, &sin_size);
        printf("Sockfd: %d\n", *new_fd);
        if (*new_fd == -1) {
            perror("accept");
            continue;
        }

        if (*countClients < BACKLOG) {
            *countClients++;
            printf("Amount of clients: %d\n", *countClients);
            if ((sockfdStored[*countClients-1] = malloc(sizeof(int))) == NULL) {
                perror("malloc");
            }
            *sockfdStored[*countClients - 1] = *new_fd;
            printf("New client has sockfd: %d and index: %d\n ", *sockfdStored[*countClients - 1], *countClients-1);
        } else {
            printf("Server is full, rejecting new client...\n");
            close(*new_fd);
            continue;
        }

        inet_ntop(their_addr.ss_family, get_in_addr((struct sockaddr *) &their_addr), s, sizeof s);
        printf("server: got connection from %s\n", s);

        if (!fork()) {
            // Child process
            close(sockfd); // Child doesn't need the listener

            // Send initial message
            if (send(*new_fd, "Hello, world!\n", 14, 0) == -1) {
                perror("send");
            }

            // Continuous loop to receive and echo back messages
            while ((num_bytes = recv(*new_fd, buffer, sizeof(buffer) - 1, 0)) > 0) {
                buffer[num_bytes] = '\0';
                printf("Received from client: %s\n", buffer);

                // Send back the same message to all connected clients
                printf("Client list is: %d\n", *countClients);
                for (int i = 0; i < *countClients; i++) {
                    if (sockfdStored[i] != NULL) {  // Check if the socket is valid
                        if (send(*sockfdStored[i], buffer, num_bytes, 0) == -1) {
                            perror("send");
                            // If send fails, remove the socket from storage
                            free(sockfdStored[i]);  // Free memory
                            sockfdStored[i] = NULL; // Mark as removed
                        }
                    }
                }
            }

            if (num_bytes == -1) {
                perror("recv");
            } else if (num_bytes == 0) {
                printf("Client disconnected.\n");
            }


            exit(0);
        }

    }
    close(*new_fd);
    return 0;
}
