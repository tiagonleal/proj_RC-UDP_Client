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

int errcode;
ssize_t n;
socklen_t addrlen;
struct addrinfo hints;
struct sockaddr_in addr;

//Struct para as funções saberem o estado da sessão
typedef struct Session {
    int fd;
    struct addrinfo *res;
    char peerport[16];
    char uid[7];
    char password[9];
    int logged_in;
} Session;


int udp_comms(Session *s, char* message, char* answer, size_t m_size){

    int lenght = strlen(message);

    for(int attempt = 0; attempt < 3; attempt++){ //Three attempts, each with a 5 second timeout.
        n = sendto(s->fd, message, lenght, 0, s->res->ai_addr, s->res->ai_addrlen);
        if(n == -1) {
            perror("Error sending message\n");
            continue;
        }

        addrlen = sizeof(addr);

        n = recvfrom(s->fd, answer, m_size - 1, 0, (struct sockaddr*)&addr, &addrlen);
        if(n == -1){
            perror("Error receiving message\n");
            continue;
        }

        answer[n] = '\0';
        return n;
    }

    perror("Error in communication\n");
    return -1;
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
    char answer[128]; //Server's answer
    int code; //Error code from the server
    char answer_code[8]; //Server's response code
    char answer_state[8]; //Server's response status

    snprintf(msg, sizeof(msg), "LIN %s %s %s\n", uid, password, s->peerport);

    code = udp_comms(s, msg, answer, sizeof(answer));
    if(code < 0) return;

    if(sscanf(answer, "%7s %7s", answer_code, answer_state) !=2) return;

    
    if(strcmp(answer_code, "RLI") != 0) {
        printf("Error\n");
        return;
    }

    int success = 0;
    if(strcmp(answer_state, "OK") == 0){
        printf("Logged in Succesfully\n");
        success = 1;
    }
    
    else if(strcmp(answer_state, "REG") == 0) {
        printf("User registered\n");
        success = 1;
    }

    else if(strcmp(answer_state, "NOK") == 0) printf("Incorrect Password\n");

    else printf("Unkown error\n");


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
        if (strcmp(estado, "NLG") == 0) printf("User not logged in\n");
        if (strcmp(estado, "UNR") == 0) printf("User not registered\n");
        if (strcmp(estado, "WRP") == 0) printf("Wrong password\n");

            
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

    
    char* ip = "tejo.tecnico.ulisboa.pt"; 
    char* port = "59000"; //Default values, can be changed by user input
    Session sessao;
    struct timeval tv;

    memset(&sessao, 0, sizeof(sessao));
    tv.tv_sec = 5;
    tv.tv_usec = 0;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-m") == 0 && i + 1 < argc) {
            strcpy(sessao.peerport, argv[i + 1]);
            i++;
        } else if (strcmp(argv[i], "-p") == 0 && i + 1 < argc) {
            port = argv[i + 1];
            i++;
        } else if (strcmp(argv[i], "-n") == 0 && i + 1 < argc) {
            ip = argv[i + 1];
            i++;
        }
    }

    int p = atoi(sessao.peerport);
    int dp = atoi(port);

    if (sessao.peerport[0] == '\0' || p < 1 || p > 65535 || dp < 1 || dp > 65535) {
        printf("Invalid Arguments\n");
        exit(1);
    }


    sessao.fd = socket(AF_INET, SOCK_DGRAM, 0); //UDP socket
    if(sessao.fd == -1) exit(1); /*error*/

    setsockopt(sessao.fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_INET; //IPv4
    hints.ai_socktype = SOCK_DGRAM; //UDP socket

    errcode = getaddrinfo(ip, port, &hints, &sessao.res);
    if (errcode != 0) exit(1); /*error*/

    commands(&sessao);

    freeaddrinfo(sessao.res);
    close(sessao.fd);
}