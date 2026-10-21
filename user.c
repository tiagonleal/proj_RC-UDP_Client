#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <stdio.h>
#include <ctype.h>
#include <sys/stat.h>

struct addrinfo hints;
int errcode;
ssize_t n;

//Struct para as funções saberem o estado da sessão
typedef struct Session {
    int fd_tcp;
    struct addrinfo *res;
    char peerport[16];
    char uid[7];
    char password[9];
    int logged_in;
    char *ip;
    char *port;
} Session;


int udp_comms(Session *s, char* message, char* answer, size_t m_size){

    size_t lenght = strlen(message);
    ssize_t n;
    socklen_t addrlen;
    struct sockaddr_in addr;
    
    int fd_udp = socket(AF_INET, SOCK_DGRAM, 0); //UDP socket
    if(fd_udp == -1){
        perror("socket");
        return -1;
    }

    struct timeval tv;
    tv.tv_sec = 5;
    tv.tv_usec = 0;

    if(setsockopt(fd_udp, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) == -1){
        perror("setsockopt");
        close(fd_udp);
        return -1;
    }

    for(int attempt = 0; attempt < 3; attempt++){ //Three attempts, each with a 5 second timeout.
        n = sendto(fd_udp, message, lenght, 0, s->res->ai_addr, s->res->ai_addrlen);
        if(n == -1) {
            perror("Error sending message\n");
            continue;
        }

        addrlen = sizeof(addr);

        n = recvfrom(fd_udp, answer, m_size - 1, 0, (struct sockaddr*)&addr, &addrlen);
        if(n == -1){
            perror("Error receiving message\n");
            continue;
        }

        answer[n] = '\0';

        close(fd_udp);
        return n;
    }

    perror("Error in communication\n");

    close(fd_udp);  
    return -1;
}


int tcp_comms(Session *s, char* message, char* answer, size_t m_size){

    s->fd_tcp= socket(AF_INET, SOCK_STREAM, 0);
    if(s->fd_tcp == -1)exit(1);

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_INET; //IPv4
    hints.ai_socktype = SOCK_STREAM; //TCP socket

    errcode = getaddrinfo(s->ip, s->port, &hints, &s->res); //////REDUNDANTE
    if (errcode != 0) exit(1); ///////N PODE FECHAR

    errcode = connect(s->fd_tcp, s->res->ai_addr, s->res->ai_addrlen);
    if (errcode == -1) exit(1);

    int lenght = strlen(message);
    int total_sent = 0;

    while (total_sent < lenght) {
        n = write(s->fd_tcp, message + total_sent, lenght - total_sent);

        if (n <= 0) {
            perror("Error writing");
            close(s->fd_tcp);
            return -1;
        }

        total_sent += n;
}

size_t total_received = 0;

while (total_received < m_size - 1) {
    n = read(s->fd_tcp, answer + total_received, m_size - 1 - total_received);

    if (n < 0) {
        perror("Error reading");
        close(s->fd_tcp);
        return -1;
    } else if (n == 0) {
        break; // Connection closed
    }

    total_received += n;

    if (memchr(answer, '\n', total_received) != NULL) {
        break;
    }
}
answer[total_received] = '\0';

close(s->fd_tcp);
return total_received;
}

int valid_chars(const char *str, int len){
    for (int i = 0; i < len; i++){
        char c = str[i];
        if (!(isalnum((unsigned char)c) || c == '-' || c == '_'))
            return 0;
    }
    return 1;
}


void login(Session* s, char* input){

    char uid[32];
    char password[32];

    //Checks for username
    if (s->logged_in){
        printf("Error. Already logged in\n");
        return;
    }

    if(sscanf(input, "login %31s %31s", uid, password) != 2){ 
        printf("Invalid Login\n");
        return;
    }

    if(strlen(uid) != 6 || strspn(uid, "0123456789") != 6) {
        printf("Invalid user\n");
        return;
    }

    //Checks for password
    if(strlen(password) != 8) {
        printf("Invalid password\n");
        return;
    }

    int valid_psswd = 1;
    for(int i = 0; i < 8; i++) {
        if(!isalnum((unsigned char)password[i])) {
            valid_psswd = 0;
            break;
        }
    }

    if(!valid_psswd) {
        printf("Invalid password\n");
        return;
    }

    // Declare variables before sending
    char msg[128]; //Message to send to server
    char resposta[128]; //Server's answer
    int code; //Error code from the server
    char codigo[8]; //Server's response code
    char estado[8]; //Server's response status

    snprintf(msg, sizeof(msg), "LIN %s %s %s\n", uid, password, s->peerport);

    code = udp_comms(s, msg, resposta, sizeof(resposta));
    if(code < 0) return;

    if(sscanf(resposta, "%7s %7s", codigo, estado) !=2) return;

    
    if(strcmp(codigo, "RLI") != 0) {
        printf("Error\n");
        return;
    }

    int success = 0;
    if(strcmp(estado, "OK") == 0){
        printf("Logged in Succesfully\n");
        success = 1;
    }
    
    else if(strcmp(estado, "REG") == 0) {
        printf("User registered\n");
        success = 1;
    }

    else if(strcmp(estado, "NOK") == 0) printf("Incorrect Password\n");

    else if(strcmp(estado, "ERR") == 0) printf("Protocol error\n");
    else printf("Unknown server response\n");


    if(success) {
        strcpy(s->uid, uid);
        strcpy(s->password, password) ;
        s->logged_in = 1;
    }
    return;

}

void logout(Session* s){
    if (!s->logged_in) {
        printf("User not logged in\n");
        return;
        }
        char resposta[128];
        char msg[128];
        int code;

        char codigo[8];
        char estado[8];
        snprintf(msg, sizeof(msg), "LOU %s %s\n", s->uid, s->password);
        code = udp_comms(s, msg, resposta, sizeof(resposta));
        if (code < 0) return;

        if (sscanf(resposta, "%7s %7s", codigo, estado) != 2) return;
        if (strcmp(codigo, "RLO") != 0) {
            printf("Error");
            return;
        }
        if (strcmp(estado, "OK") == 0){
            printf("Logged out Succesfully\n");
            s->logged_in = 0;
        }
        else if (strcmp(estado, "NLG") == 0) printf("User not logged in\n");
        else if (strcmp(estado, "UNR") == 0) printf("User not registered\n");
        else if (strcmp(estado, "WRP") == 0) printf("Wrong password\n");
        else if(strcmp(estado, "ERR") == 0) printf("Protocol error\n");
        else printf("Unknown server response\n");
}

void unregister(Session* s){
    if (!s->logged_in) {
        printf("User not logged in\n");
        return;
    }
    char resposta[128];
    char msg[128];
    int code;

    char codigo[8];
    char estado[8];

    snprintf(msg, sizeof(msg), "UNR %s %s\n", s->uid, s->password);
    code = udp_comms(s, msg, resposta, sizeof(resposta));

    if (code < 0) return;

    if (sscanf(resposta, "%7s %7s", codigo, estado) != 2) return;
    if (strcmp(codigo, "RUR") != 0) {
        printf("Error"); 
        return;
    }
    if (strcmp(estado, "OK") == 0){
        printf("Unregistered Succesfully\n");
        s->logged_in = 0;
    }
    else if(strcmp(estado, "NOK") == 0) printf("User not logged in\n");
    else if(strcmp(estado, "UNR") == 0) printf("User not registered\n");
    else if(strcmp(estado, "WRP") == 0) printf("Wrong password\n");
    else if(strcmp(estado, "ERR") == 0) printf("Protocol error\n");
    else printf("Unknown server response\n");
}

void publish(Session* s, char* input){
    if(!s->logged_in) {
        printf("User not logged in\n");
        return;
    }
    char command[32], filename[32], label[32];

    if (sscanf(input, "%31s %31s %31s", command, filename, label) != 3){
        printf("Invalid arguments\n");
        return;
    }

    if (strlen(filename) > 24){
        printf("File name too big\n");
        return;
    }
    char* dot = strrchr(filename, '.');
    if (dot == NULL || dot == filename || strlen(dot + 1) != 3 || !valid_chars(filename, dot - filename)){
        printf("Invalid File Name\n");
        return;
    }

    for (int i = 1; i <= 3; i++){
        if (!isalnum((unsigned char)dot[i])){
            printf("Invalid File Name\n");
            return;
        }
    }
    if (!valid_chars(label, strlen(label)) || strlen(label) > 20){
        printf("Invalid Label\n");
        return;
    }

    struct stat file_info;
    if (stat(filename, &file_info) != 0 || !S_ISREG(file_info.st_mode) ||
            file_info.st_size > 10000000 || file_info.st_size < 0) {
        printf("File not available\n");
        return;
    }
    
    char msg[128]; //Message to send to server
    char answer[128]; //Server's answer
    int code; //Error code from the server
    char answer_code[8]; //Server's response code
    char answer_state[8]; //Server's response status
    snprintf(msg, sizeof(msg), "PUB %s %s %s %d %s\n", s->uid, s->password, filename, (int)file_info.st_size, label);
    code = udp_comms(s, msg, answer, sizeof(answer));
    if (code < 0) return;

    if (sscanf(answer, "%7s %7s", answer_code, answer_state) != 2) return;
    if (strcmp(answer_code, "RPB") != 0) {
        printf("Error\n");
        return;
    }
    if (strcmp(answer_state, "OK") == 0) printf("Published Successfully\n");
    else if(strcmp(answer_state, "NOK") == 0) printf("Could not publish\n");
    else if(strcmp(answer_state, "NLG") == 0) printf("User not logged in\n");
    else if(strcmp(answer_state, "UNR") == 0) printf("User not registered\n");
    else if(strcmp(answer_state, "WRP") == 0) printf("Wrong password\n");
    else if(strcmp(answer_state, "ERR") == 0) printf("Protocol error\n");
    else printf("Unknown error\n");
}

void remove_resource(Session* s, char* filename){
    if (!s->logged_in) {
        printf("User not logged in\n");
        return;
    }

    char resposta[128];
    char msg[128];
    int code;

    char codigo[8];
    char estado[8];

    snprintf(msg, sizeof(msg), "REM %s %s %s\n", s->uid, s->password, filename);
    code = udp_comms(s, msg, resposta, sizeof(resposta));

    if (code < 0) return;
    if (sscanf(resposta, "%7s %7s", codigo, estado) != 2) return;

    if (strcmp(codigo, "RRM") != 0) {
        printf("Error"); 
        return;
    }

    if (strcmp(estado, "OK") == 0){
        printf("Resource remove Successfully\n");
    }
    else if(strcmp(estado, "NLG") == 0) printf("User not logged in\n");
    else if(strcmp(estado, "UNR") == 0) printf("User not registered\n");
    else if(strcmp(estado, "WRP") == 0) printf("Wrong password\n");
    else if(strcmp(estado, "NOK") == 0) printf("Resource not published\n");
    else if(strcmp(estado, "ERR") == 0) printf("Protocol error\n");
    else printf("Unknown server response\n");

}

void list(Session* s){
    char resposta[2048];
    char msg[128];
    int code;

    char codigo[8];
    char estado[8];

    snprintf(msg, sizeof(msg), "LST\n");
    code = udp_comms(s, msg, resposta, sizeof(resposta));

    if (code < 0) return;
    if (sscanf(resposta, "%7s %7s", codigo, estado) != 2) return;

    if (strcmp(codigo, "RLS") != 0) {
        printf("Error"); 
        return;
    }

    if (strcmp(estado, "OK") == 0) {

    printf("Files: %s\n", resposta+ 7); // RLS OK são 7 caracteres    
    }
    else if(strcmp(estado, "NOK") == 0) printf("No resources available\n");
    else if(strcmp(estado, "ERR") == 0) printf("Protocol error\n");
    else printf("Unknown server response\n");
}

void commands (Session *s) {
    char input[256];
    char command[32];

    while(1){
        printf("> ");

        if(fgets(input, sizeof(input), stdin) == NULL) break;

        if(sscanf(input, "%31s", command) != 1) continue;

        if(strcmp(command, "login") == 0){
            login(s, input);
            continue;
        }

        else if(strcmp(command, "logout") == 0){
            logout(s);
            continue;
        }

        else if(strcmp(command, "unregister") == 0){    
            unregister(s);
            continue;
        }

        else if(strcmp(command, "remove") == 0){
            char filename[128];
            if(sscanf(input, "remove %127s", filename) != 1) {
                printf("Invalid remove command\n");
                continue;
            }
            remove_resource(s, filename);
            continue;
        }

        else if(strcmp(command, "list") == 0){
            list(s);
            continue;
        }

        else if(strcmp(command, "publish") == 0){
            publish(s, input);
            continue;
        } 

        else if(strcmp(command, "exit") == 0){ 
            if(s->logged_in) {
                printf("Logout first\n");
                continue;
            }
            else {
                printf("Exiting");
                break;
            }
        }

        else printf("Invalid Command\n");
    }
}


int main(int argc, char *argv[]){

    Session sessao;
    memset(&sessao, 0, sizeof(sessao));

    sessao.ip = "tejo.tecnico.ulisboa.pt"; 
    sessao.port = "59000"; //Default values, can be changed by user input

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-m") == 0 && i + 1 < argc) {
            strcpy(sessao.peerport, argv[i + 1]);
            i++;
        } else if (strcmp(argv[i], "-p") == 0 && i + 1 < argc) {
            sessao.port = argv[i + 1];
            i++;
        } else if (strcmp(argv[i], "-n") == 0 && i + 1 < argc) {
            sessao.ip = argv[i + 1];
            i++;
        }
    }

    int p = atoi(sessao.peerport);
    int dp = atoi(sessao.port);
    if (sessao.peerport[0] == '\0' || p < 1 || p > 65535 || dp < 1 || dp > 65535) {
        printf("Invalid Arguments\n");
        exit(1);
    }

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_INET; //IPv4
    hints.ai_socktype = SOCK_DGRAM; //UDP socket

    errcode = getaddrinfo(sessao.ip, sessao.port, &hints, &sessao.res);
    if (errcode != 0) exit(1); /*error*/

    commands(&sessao);

    freeaddrinfo(sessao.res);
}