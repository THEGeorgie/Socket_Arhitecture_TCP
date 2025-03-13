/*
** server.c -- a stream socket server demo
*/

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
#include <sys/ipc.h>
#include <sys/shm.h>
#include <signal.h>
#include <time.h>
#include <fcntl.h>
#include <pthread.h>
#include <semaphore.h>
#include <stdio.h>      // printf, perror
#include <stdlib.h>     // exit, EXIT_FAILURE
#include <sys/mman.h>   // mmap, munmap, MAP_SHARED, MAP_ANONYMOUS, PROT_READ, PROT_WRITE
#include <sys/types.h>

#define PORT "3490"  // the port users will be connecting to
#define MAXDATASIZE 100
#define BACKLOG 10	 // how many pending connections queue will hold

void sigchld_handler(int s) {
    (void) s; // quiet unused variable warning

    // waitpid() might overwrite errno, so we save and restore it:
    int saved_errno = errno;

    while (waitpid(-1, NULL, WNOHANG) > 0);

    errno = saved_errno;
}

// get sockaddr, IPv4 or IPv6:
void *get_in_addr(struct sockaddr *sa) {
    if (sa->sa_family == AF_INET) {
        return &(((struct sockaddr_in *) sa)->sin_addr);
    }

    return &(((struct sockaddr_in6 *) sa)->sin6_addr);
}

int main(void) {
    int sockfd, new_fd; // listen on sock_fd, new connection on new_fd
    struct addrinfo hints, *servinfo, *p;
    struct sockaddr_storage their_addr; // connector's address information
    socklen_t sin_size;
    struct sigaction sa;
    int yes = 1;
    char s[INET6_ADDRSTRLEN];
    int rv;
    char *buf[MAXDATASIZE];
    int numbytes = 0;
    time_t now;
    struct tm * local_time;
    char time_str[9];
    char msg[MAXDATASIZE];

    int shmid;
    key_t key = IPC_PRIVATE; // Use a unique key

    // Create the shared memory segment
    size_t shared_size = sizeof(int) + MAXDATASIZE + BACKLOG;
    if ((shmid = shmget(key, shared_size, IPC_CREAT | 0666)) < 0) {
        perror("shmget");
        exit(1);
    }

    // Attach the shared memory segment to the process's address space
    void *shmaddr = shmat(shmid, NULL, 0);
    if (shmaddr == (void *) -1) {
        perror("shmat");
        exit(1);
    }

    int *broadcast = (int *) shmaddr;
    char *broadcast_msg = (char *) (broadcast + 1); // char array starts after the int
    int * client_list = (int *) (broadcast + 1 + MAXDATASIZE);
    *broadcast = 0;

    sem_t mutex;
    sem_init(&mutex, 0, 1);
    if (&mutex == SEM_FAILED) {
        perror("sem_open failed");
        exit(1);
    }

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE; // use my IP

    if ((rv = getaddrinfo(NULL, PORT, &hints, &servinfo)) != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
        return 1;
    }

    // loop through all the results and bind to the first we can
    for (p = servinfo; p != NULL; p = p->ai_next) {
        if ((sockfd = socket(p->ai_family, p->ai_socktype,
                             p->ai_protocol)) == -1) {
            perror("server: socket");
            continue;
        }

        if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes,
                       sizeof(int)) == -1) {
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

    freeaddrinfo(servinfo); // all done with this structure

    if (p == NULL) {
        fprintf(stderr, "server: failed to bind\n");
        exit(1);
    }

    if (listen(sockfd, BACKLOG) == -1) {
        perror("listen");
        exit(1);
    }

    sa.sa_handler = sigchld_handler; // reap all dead processes
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    if (sigaction(SIGCHLD, &sa, NULL) == -1) {
        perror("sigaction");
        exit(1);
    }

    printf("server: waiting for connections...\n");
    while (1) {
        // main accept() loop
        sin_size = sizeof their_addr;
        new_fd = accept(sockfd, (struct sockaddr *) &their_addr, &sin_size);
        if (new_fd == -1) {
            perror("accept");
            continue;
        }

        sem_wait(&mutex);
        for (int i = 0; i < BACKLOG; i++) {
            if (client_list[i] == 0) {
                client_list[i] = new_fd;
                break;
            }
        }
        sem_post(&mutex);

        inet_ntop(their_addr.ss_family,
                  get_in_addr((struct sockaddr *) &their_addr),
                  s, sizeof s);
        printf("server: got connection from %s\n", s);

        if (!fork()) {
            // this is the child process
            close(sockfd); // child doesn't need the listener
            time(&now);
            local_time = localtime(&now);

            sprintf(time_str, "%02d:%02d:%02d", local_time->tm_hour, local_time->tm_min, local_time->tm_sec);
            snprintf(msg, sizeof(msg), "from: server Wellcome please wait!:%s", time_str);
            if (send(new_fd, msg, sizeof(msg), 0) == -1)
                perror("send");

            pid_t pidGchild = fork();
            if (pidGchild == -1) {
                perror("fork");
                exit(1);
            }

            while (1) {
                if (pidGchild == 0) {
                    if (send(new_fd, "Started", strlen("Started"), 0) == -1)
                        perror("send");
                    while (1) {
                        sem_wait(&mutex);
                        if (*broadcast == 1) {
                            printf("server: sending broadcast message from proces %d;\n", new_fd);
                            if (send(new_fd, broadcast_msg, strlen(broadcast_msg), 0) == -1) {
                                perror("send");
                            }
                            *broadcast = 0;
                        }
                        sem_post(&mutex);
                    }
                }else {
                    if ((numbytes = recv(new_fd, buf, MAXDATASIZE, 0)) == -1) {
                        perror("recv");
                    } else if (numbytes == 0) {
                        printf("server: connection closed\n");
                        sem_wait(&mutex);
                        for (int i = 0; i < BACKLOG; i++) {
                            if (client_list[i] == new_fd) {
                                client_list[i] = 0;
                                break;
                            }
                        }
                        sem_post(&mutex);
                        break;
                    }

                    buf[numbytes] = '\0';

                    sem_wait(&mutex);
                    time(&now);
                    local_time = localtime(&now);
                    memset(msg, 0, sizeof(msg)/sizeof(msg[0]));
                    sprintf(time_str, "%02d:%02d:%02d", local_time->tm_hour, local_time->tm_min, local_time->tm_sec);
                    snprintf(msg, sizeof(msg), "from: client(%d) %s:%s", new_fd, buf, time_str);
                    printf("server: sending %s\n", msg);
                    strcpy(broadcast_msg, msg);
                    *broadcast = 1;
                    sem_post(&mutex);
                }
            }


            //close(new_fd);
            exit(0);
        }
    }
    close(new_fd);

    shmdt(shmaddr);
    shmctl(shmid, IPC_RMID, NULL);
    sem_destroy(&mutex);
    return 0;
}
