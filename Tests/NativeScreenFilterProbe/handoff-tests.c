#include "ScreenSystem.h"
#include <assert.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>

int main(int argc, char **argv) {
    assert(argc == 2); alarm(10);
    char root[] = "/private/tmp/sliccy-handoff.XXXXXX"; assert(mkdtemp(root));
    struct sockaddr_un address = {.sun_family=AF_UNIX};
    snprintf(address.sun_path,sizeof(address.sun_path),"%s/lane",root);
    int listener=socket(AF_UNIX,SOCK_STREAM,0); assert(listener>=0);
    assert(!bind(listener,(struct sockaddr*)&address,sizeof(address)) && !listen(listener,1));
    int sync[2]; assert(!socketpair(AF_UNIX,SOCK_STREAM,0,sync));
    pid_t peer=fork(); assert(peer>=0);
    if (!peer) {
        close(listener); close(sync[0]);
        int lane=socket(AF_UNIX,SOCK_STREAM,0); assert(lane>=0);
        assert(!connect(lane,(struct sockaddr*)&address,sizeof(address)));
        char record[5]; assert(read(lane,record,5)==5 && !memcmp(record,"probe",5));
        assert(write(sync[1],"x",1)==1);
        char end; assert(read(sync[1],&end,1)==1);
        close(lane); _exit(0);
    }
    close(sync[1]); int lane=accept(listener,NULL,NULL); assert(lane>=0);
    pid_t helper=0; int channel=-1, output=-1;
    assert(!sliccy_screen_proof_helper_spawn(argv[1],&helper,&channel,&output));
    assert(!kill(helper,SIGCONT));
    char bytes[1024]={0}; size_t length=0;
    while (length<sizeof(bytes)-1) {assert(read(output,bytes+length,1)==1);if(bytes[length++]=='\n')break;}
    assert(!strcmp(bytes,"{\"stage\":\"ready\"}\n"));
    assert(!sliccy_screen_proof_handoff(channel,lane,peer,"probe",5));
    char observed; assert(read(sync[0],&observed,1)==1);
    assert(fcntl(lane,F_GETFD)>=0); // Parent retained original descriptor after transfer.
    ssize_t n;
    while ((n=read(output,bytes+length,sizeof(bytes)-1-length))>0) length+=(size_t)n;
    assert(n==0); bytes[length]=0;
    assert(strstr(bytes,"\"received\"") && strstr(bytes,"\"write-started\"") && strstr(bytes,"\"written\"") && strstr(bytes,"\"held\"") && strstr(bytes,"\"complete\""));
    assert(!strstr(bytes,"failed"));
    int status; assert(waitpid(helper,&status,0)==helper && WIFEXITED(status) && !WEXITSTATUS(status));
    assert(fcntl(lane,F_GETFD)>=0);
    assert(write(sync[0],"x",1)==1); assert(waitpid(peer,&status,0)==peer && WIFEXITED(status) && !WEXITSTATUS(status));
    close(channel);close(output);close(lane);close(listener);close(sync[0]);unlink(address.sun_path);rmdir(root);
    puts("PASS: owned helper receives real stream FD, writes exact record, holds it, exits/reaps; parent retains original");
}
