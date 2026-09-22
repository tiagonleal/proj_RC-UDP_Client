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
char buffer[128];

//Struct para as funções saberem o estado da sessão
typedef struct Session {
    int fd;
    struct addrinfo *res;
    char peerport[16];
    char uid[7];
    char password[9];
    int logged_in;
} Session;


/** Mapa
 * 1 - Valid Login
 * 2 - Invalid Login
 * 3 - User registered and logged in
 * 
 * 11 - Valid Logout
 * 12 - No user logged in
 * 13 - User not registered
 * 14 - Wrong Password
 * 
 * 21 - Unregistered succesfully
 * 22 - No user logged in
 * 23 - No user registered
 * 24 - Wrong Password
 */

int udp_comms(Session *s, char* mensagem, char* resposta, size_t tamanho){

    int lenght = strlen(mensagem);

    n = sendto(s->fd, mensagem, lenght, 0, s->res->ai_addr, s->res->ai_addrlen);
    if(n == -1) {
        perror("Error sending message");
        return n;
    }

    addrlen = sizeof(addr);
    n = recvfrom(s->fd, resposta, tamanho - 1, 0, (struct sockaddr*)&addr, &addrlen);
    //Timeout? - COmo configurar?
    if(n == -1) {
        perror("Error receiving message");
        return n;
    }

    resposta[n] = '\0';
    return n;
}


void commands (Session *s) {
    char input[256];
    char command[32];
    char uid[32];
    char password[32];
    
    while(1){
        printf("> ");

        if(fgets(input, sizeof(input), stdin) == NULL) break;

        if(sscanf(input, "%31s", command) != 1) continue;

        if(strcmp(command, "login") == 0){
            
            if(sscanf(input, "login %31s %31s", uid, password) != 2){ 
                printf("Login Inválido\n");
                continue;
            }

            // Talvez simplificar

            if(strlen(uid) != 6) {
                printf("Utilizador Inválido.\n");
                continue;
            }

            int uid_valido = 1;

            for(int i = 0; i < 6; i++) {
                if(!isdigit((unsigned char)uid[i])) {
                    uid_valido = 0;
                    break;
                }
            }

            if(!uid_valido) {
                printf("Utilizador inválido.\n");
                continue;
            }

            if(strlen(password) != 8) {
                printf("Password Inválida.\n");
                continue;
            }

            int password_valida = 1;

            for(int i = 0; i < 8; i++) {
                if(!isalnum((unsigned char)password[i])) {
                    password_valida = 0;
                    break;
                }
            }

            if(!password_valida) {
                printf("Password inválida.\n");
                continue;
            }

            char resposta[128];
            char msg[128];
            int code;

            char codigo[8];
            char estado[8];
            snprintf(msg, sizeof(msg), "LIN %s %s %s\n", uid, password, s->peerport);
            code = udp_comms(s, msg, resposta, sizeof(resposta));
            if(code < 0) continue;
            if(sscanf(resposta, "%s %s", codigo, estado) !=2) continue;
            if(strcmp(codigo, "RLI") != 0) printf("Error");

            if(strcmp(estado, "OK") == 0) {
                printf("Logged in Succesfully\n");
                strcpy(s->uid, uid);
                strcpy(s->password, password) ;
                s->logged_in =1;
            }

            if(strcmp(estado, "NOK") == 0) printf("Incorrect Password\n");

            if(strcmp(estado, "REG") == 0) {
                printf("User registered\n");
                strcpy(s->uid, uid);
                strcpy(s->password, password) ;
                s->logged_in =1;
            }
        }

        else if(strcmp(command, "logout") == 0){ //printf("Efetuar logout.\n");
            if (!s->logged_in) {
                printf("User not logged in\n");
                continue;
            }
            char resposta[128];
            char msg[128];
            int code;

            char codigo[8];
            char estado[8];
            snprintf(msg, sizeof(msg), "LOU %s %s\n", s->uid, s->password);
            code = udp_comms(s, msg, resposta, sizeof(resposta));
            if (code < 0) continue;

            if (sscanf(resposta, "%s %s", codigo, estado) != 2) continue;
            if (strcmp(codigo, "RLO") != 0) printf("Error");
            if (strcmp(estado, "OK") == 0){
                printf("Logged out Succesfully\n");
                s->logged_in = 0;
            }
            if (strcmp(estado, "NLG") == 0) printf("User not logged in\n");
            if (strcmp(estado, "UNR") == 0) printf("User not registered\n");
            if (strcmp(estado, "WRP") == 0) printf("Wrong password\n");

        }

        else if(strcmp(command, "unregister") == 0){ 
            if(!s->logged_in) {
                printf("User not logged in\n");
                continue;
            }
            char resposta[128];
            char msg[128];
            int code;

            char codigo[8];
            char estado[8];

            snprintf(msg, sizeof(msg), "UNR %s %s\n", s->uid, s->password);
            code = udp_comms(s, msg, resposta, sizeof(resposta));

            if (code < 0) continue;

            if (sscanf(resposta, "%s %s", codigo, estado) != 2) continue;
            if (strcmp(codigo, "RUR") != 0) printf("Error"); // Sqe fazemos um continue depois disto
            if (strcmp(estado, "OK") == 0){
                printf("Unregistered Succesfully\n");
                s->logged_in = 0;
            }
            else if(strcmp(estado, "NOK") == 0) printf("User not logged in\n");
            else if(strcmp(estado, "UNR") == 0) printf("User not registered\n");
            else if(strcmp(estado, "WRP") == 0) printf("Wrong password\n");
        }

        else if(strcmp(command, "exit") == 0){ 
            if(s->logged_in) {
                printf("User logged in\n");
                continue;
            }
            else break;
        }

        else printf("Comando Inválido.\n");
    }
}


int main(int argc, char *argv[]){

    
    char* ip = "tejo.tecnico.ulisboa.pt"; 
    char* port = "59000"; //Default value, can be changed by user input
    //char* peerport = NULL;
    Session sessao;
    memset(&sessao, 0, sizeof(sessao));


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

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_INET; //IPv4
    hints.ai_socktype = SOCK_DGRAM; //UDP socket

    errcode = getaddrinfo(ip, port, &hints, &sessao.res);
    if (errcode != 0) exit(1); /*error*/

    commands(&sessao);

    freeaddrinfo(sessao.res);
    close(sessao.fd);
}