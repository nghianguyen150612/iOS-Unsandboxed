#define _GNU_SOURCE 1
#if defined(__APPLE__)
#define _DARWIN_C_SOURCE 1
#endif
#include "iu_service_lifecycle.h"

#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <spawn.h>
#include <signal.h>
#include <stdint.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

extern char **environ;

#define LABEL "com.ios-unsandboxed.daemon"
#define STAGED "/var/lib/ios-unsandboxed/com.ios-unsandboxed.daemon.plist.inactive"
#define ACTIVE "/Library/LaunchDaemons/com.ios-unsandboxed.daemon.plist"
#define RECORD "/var/lib/ios-unsandboxed/service-registration"
#define JOURNAL "/var/lib/ios-unsandboxed/service-transaction"
#define LAUNCHCTL_OUTPUT_MAX 65536U
#if defined(IU_INSTALLER_TESTING)
#define TIMEOUT_SECONDS 2
#else
#define TIMEOUT_SECONDS 5
#endif

enum job_state { JOB_UNKNOWN = -1, JOB_ABSENT = 0, JOB_LOADED = 1 };
enum process_state { PROCESS_UNKNOWN = -1, PROCESS_STOPPED = 0, PROCESS_RUNNING = 1 };

static int path_join(char *out, size_t cap, const char *root, const char *path)
{
    int n;
    if (strcmp(root, "/") == 0) n = snprintf(out, cap, "%s", path);
    else n = snprintf(out, cap, "%s%s", root, path);
    return n >= 0 && (size_t)n < cap ? 0 : -1;
}

static int sync_parent_path(const char *path)
{
    char directory[4096]; char *slash; int fd, result;
    if(strlen(path)>=sizeof(directory))return -1;
    strcpy(directory,path);slash=strrchr(directory,'/');if(slash==NULL)return -1;
    if(slash==directory)slash[1]='\0';else *slash='\0';
    fd=open(directory,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);if(fd<0)return -1;
    result=fsync(fd);if(result!=0&&(errno==EINVAL||errno==ENOTSUP||errno==EOPNOTSUPP))result=0;
    close(fd);return result;
}

static int unlink_sync(const char *path)
{
    if(unlink(path)!=0)return -1;
    return sync_parent_path(path);
}

#if defined(IU_INSTALLER_TESTING)
static int fixture_mock_path(const char *root, const char *relative, char *out, size_t cap)
{
    char copy[4096],*save=NULL,*part;struct stat st;int fd;
    if(relative==NULL||relative[0]!='/'||strlen(relative)>=sizeof(copy)||strstr(relative,"//")!=NULL)return -1;
    strcpy(copy,relative);part=strtok_r(copy,"/",&save);
    while(part!=NULL){if(!strcmp(part,".")||!strcmp(part,".."))return -1;part=strtok_r(NULL,"/",&save);}
    if(path_join(out,cap,root,relative)!=0)return -1;
    fd=open(out,O_RDONLY|O_NOFOLLOW|O_CLOEXEC|O_NONBLOCK);if(fd<0)return -1;
    if(fstat(fd,&st)!=0||!S_ISREG(st.st_mode)||st.st_nlink!=1||st.st_uid!=geteuid()||
       (st.st_mode&0111)==0||(st.st_mode&0022)!=0){close(fd);errno=EPERM;return -1;}
    close(fd);return 0;
}
#endif

static int run_launchctl(const char *root, int fixture, const char *verb,
                         const char *operand, int *exit_code, char *captured, size_t captured_cap)
{
    char diagnostic[LAUNCHCTL_OUTPUT_MAX+1U]; pid_t pid; int status,pipes[2],error; size_t used=0; struct timespec start, now;
    const char *path = "/bin/launchctl";
#if defined(IU_INSTALLER_TESTING)
    char executable[4096];
    if (fixture && getenv("IU_LAUNCHCTL_MOCK") != NULL) {
        if (fixture_mock_path(root,getenv("IU_LAUNCHCTL_MOCK"),executable,sizeof(executable)) != 0) return -1;
        path = executable;
    } else if (fixture) {
        errno=ENOSYS; return -1;
    }
#else
    (void)root; (void)fixture;
#endif
    char *argv[4]={(char *)path,(char *)verb,NULL,NULL};
    if(operand!=NULL)argv[2]=(char *)operand;
    posix_spawn_file_actions_t actions;
    if(pipe(pipes)!=0)return -1;
    (void)fcntl(pipes[0],F_SETFD,FD_CLOEXEC);(void)fcntl(pipes[1],F_SETFD,FD_CLOEXEC);
    if(posix_spawn_file_actions_init(&actions)!=0){close(pipes[0]);close(pipes[1]);return -1;}
    if(posix_spawn_file_actions_adddup2(&actions,pipes[1],STDOUT_FILENO)!=0||
       posix_spawn_file_actions_adddup2(&actions,pipes[1],STDERR_FILENO)!=0||
       posix_spawn_file_actions_addclose(&actions,pipes[0])!=0||
       posix_spawn_file_actions_addclose(&actions,pipes[1])!=0){posix_spawn_file_actions_destroy(&actions);close(pipes[0]);close(pipes[1]);return -1;}
    error = posix_spawn(&pid, path, &actions, NULL, argv, environ);
    posix_spawn_file_actions_destroy(&actions);close(pipes[1]);
    if (error != 0) { close(pipes[0]);errno = error; return -1; }
    (void)fcntl(pipes[0],F_SETFL,O_NONBLOCK);
    (void)clock_gettime(CLOCK_MONOTONIC, &start);
    for (;;) {
        for(;;){char block[128];ssize_t count=read(pipes[0],block,sizeof(block));if(count>0){size_t keep=(size_t)count;if(keep>sizeof(diagnostic)-1U-used)keep=sizeof(diagnostic)-1U-used;if(keep){memcpy(diagnostic+used,block,keep);used+=keep;}continue;}if(count<0&&errno==EINTR)continue;break;}
        pid_t waited = waitpid(pid, &status, WNOHANG);
        if (waited == pid) break;
        if (waited < 0 && errno != EINTR) {close(pipes[0]);return -1;}
        (void)clock_gettime(CLOCK_MONOTONIC, &now);
        if (now.tv_sec - start.tv_sec >= TIMEOUT_SECONDS) {
            (void)kill(pid, SIGKILL); (void)waitpid(pid, &status, 0);close(pipes[0]);errno = ETIMEDOUT; return -1;
        }
        { struct timespec pause = {0, 50000000L}; (void)nanosleep(&pause, NULL); }
    }
    for(;;){char block[128];ssize_t count=read(pipes[0],block,sizeof(block));if(count>0){size_t keep=(size_t)count;if(keep>sizeof(diagnostic)-1U-used)keep=sizeof(diagnostic)-1U-used;if(keep){memcpy(diagnostic+used,block,keep);used+=keep;}continue;}if(count<0&&errno==EINTR)continue;break;}
    close(pipes[0]);diagnostic[used]='\0';
    if(captured!=NULL&&captured_cap>0){size_t copy=used<captured_cap-1U?used:captured_cap-1U;memcpy(captured,diagnostic,copy);captured[copy]='\0';}
    if (WIFEXITED(status)) *exit_code = WEXITSTATUS(status);else *exit_code=128;
    if(*exit_code!=0&&used>0)fprintf(stderr,"launchctl %s: %.512s\n",verb,diagnostic);
    return 0;
}

static int parse_list_output(const char *output, int *process)
{
    char copy[LAUNCHCTL_OUTPUT_MAX+1U],*line_save=NULL,*line;
    if(strlen(output)>=sizeof(copy))return JOB_UNKNOWN;
    strcpy(copy,output);line=strtok_r(copy,"\n",&line_save);
    int valid_header=0;
    while(line!=NULL){char pid[32],status[32],label[128],extra;int fields=sscanf(line,"%31s %31s %127s %c",pid,status,label,&extra);
        if(fields==3&&strcmp(pid,"PID")==0&&strcmp(status,"Status")==0&&strcmp(label,"Label")==0)valid_header=1;
        if(fields>=3&&strcmp(label,LABEL)==0){
            if(strcmp(pid,"-")==0){*process=PROCESS_STOPPED;return JOB_LOADED;}
            if(pid[0]>='0'&&pid[0]<='9'){char *end=NULL;unsigned long value=strtoul(pid,&end,10);if(end!=pid&&*end=='\0'&&value>0){*process=PROCESS_RUNNING;return JOB_LOADED;}}
            return JOB_UNKNOWN;
        }
        line=strtok_r(NULL,"\n",&line_save);
    }
    if(valid_header){*process=PROCESS_STOPPED;return JOB_ABSENT;}
    return JOB_UNKNOWN;
}

static int query_launchd(const char *root, int fixture, int *process)
{
    char output[LAUNCHCTL_OUTPUT_MAX+1U]="";int status=0,result;
    *process=PROCESS_UNKNOWN;
    if(run_launchctl(root,fixture,"list",NULL,&status,output,sizeof(output))!=0)return JOB_UNKNOWN;
    if(strlen(output)>=LAUNCHCTL_OUTPUT_MAX)return JOB_UNKNOWN;
    if(status!=0)return JOB_UNKNOWN;
    result=parse_list_output(output,process);
    return result;
}

static int read_regular_links(const char *path, char *buf, size_t cap, struct stat *st, nlink_t links)
{
    int fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK); size_t used=0;
    if (fd < 0) return -1;
    if (fstat(fd, st) != 0 || !S_ISREG(st->st_mode) || st->st_nlink != links ||
        (st->st_mode & 0022) != 0 || st->st_size < 0 || (uint64_t)st->st_size >= cap) { close(fd); errno=EPERM; return -1; }
    while (used < cap) { ssize_t n=read(fd,buf+used,cap-used); if(n>0){used+=(size_t)n;continue;} if(n==0)break; if(errno==EINTR)continue; close(fd);return -1; }
    close(fd); if (used == cap) { errno=EFBIG; return -1; } buf[used]='\0'; return (int)used;
}

static int read_regular(const char *path, char *buf, size_t cap, struct stat *st)
{
    return read_regular_links(path,buf,cap,st,1);
}

static int verified_active(const char *active, const char *staged, int *exists)
{
    char a[8192], s[8192]; struct stat ast, sst; int al, sl;
    sl=read_regular(staged,s,sizeof(s),&sst); if(sl<0)return -1;
    al=read_regular(active,a,sizeof(a),&ast);
    if(al<0){if(errno==ENOENT){*exists=0;return 0;}return -1;}
    if(ast.st_uid!=sst.st_uid||ast.st_gid!=sst.st_gid||(ast.st_mode&07777)!=0644||al!=sl||memcmp(a,s,(size_t)sl)!=0){errno=EPERM;return -1;}
    *exists=1;return 0;
}

static int verify_active_parent(const char *root, int fixture, uid_t uid, gid_t gid)
{
    int rootfd=-1, library=-1, daemons=-1; struct stat st; int result=-1;
    if(strcmp(root,"/")==0)rootfd=open("/",O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
    else rootfd=open(root,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
    if(rootfd<0)return -1;
    library=openat(rootfd,"Library",O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
    if(library<0||fstat(library,&st)!=0||!S_ISDIR(st.st_mode)||st.st_uid!=uid||st.st_gid!=gid||(st.st_mode&0022)!=0)goto done;
    daemons=openat(library,"LaunchDaemons",O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
    if(daemons<0||fstat(daemons,&st)!=0||!S_ISDIR(st.st_mode)||st.st_uid!=uid||st.st_gid!=gid||(st.st_mode&0022)!=0)goto done;
    result=0;
done:
    if(daemons>=0)close(daemons);
    if(library>=0)close(library);
    if(rootfd>=0)close(rootfd);
    (void)fixture;return result;
}

static int ensure_log_directory(const char *root, int fixture, uid_t uid, gid_t gid)
{
    char path[4096]; int parent=-1, logs=-1,created=0; struct stat st; int result=-1;
    if(path_join(path,sizeof(path),root,"/var/log")!=0)return -1;
    parent=open(path,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
    if(parent<0||fstat(parent,&st)!=0||!S_ISDIR(st.st_mode)||st.st_uid!=uid||st.st_gid!=gid||(st.st_mode&0022)!=0)goto done;
    if(mkdirat(parent,"ios-unsandboxed",0700)==0)created=1;else if(errno!=EEXIST)goto done;
    logs=openat(parent,"ios-unsandboxed",O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
    if(logs<0||fstat(logs,&st)!=0||!S_ISDIR(st.st_mode))goto done;
    if(created&&fchown(logs,uid,gid)!=0)goto done;
    if(created&&fchmod(logs,0700)!=0)goto done;
    if(fstat(logs,&st)!=0||st.st_uid!=uid||st.st_gid!=gid||(st.st_mode&07777)!=0700)goto done;
    if(created){int sync_result=fsync(parent);if(sync_result!=0&&errno!=EINVAL&&errno!=ENOTSUP&&errno!=EOPNOTSUPP)goto done;}
    result=0;
done:
    if(logs>=0)close(logs);
    if(parent>=0)close(parent);
    (void)fixture;return result;
}

static int service_identity(int fixture, uid_t *uid, gid_t *gid)
{
    struct group *wheel;
    if(fixture){*uid=geteuid();*gid=getegid();return 0;}
    wheel=getgrnam("wheel");if(wheel==NULL)return -1;*uid=0;*gid=wheel->gr_gid;return 0;
}

static int write_record(const char *record, const char *state, int fixture)
{
    char temp[4096]; int fd; struct stat st;uid_t uid;gid_t gid; int inspected=lstat(record,&st);
    if(service_identity(fixture,&uid,&gid)!=0)return -1;
    if (inspected==0 && (!S_ISREG(st.st_mode)||st.st_nlink!=1||(st.st_mode&0022)!=0)) { errno=EPERM; return -1; }
    if (inspected!=0 && errno!=ENOENT) return -1;
    if (snprintf(temp,sizeof(temp),"%s.tmp",record)<0)return -1;
    fd=open(temp,O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0600); if(fd<0)return -1;
    { const char text[]="ios-unsandboxed-service\nschema_version=1\nlabel=" LABEL "\nstate=";
      if(fchown(fd,uid,gid)!=0||write(fd,text,sizeof(text)-1)!=(ssize_t)(sizeof(text)-1)||write(fd,state,strlen(state))!=(ssize_t)strlen(state)||write(fd,"\n",1)!=1||fchmod(fd,0600)!=0||fsync(fd)!=0){int e=errno;close(fd);unlink(temp);errno=e;return -1;} }
    if(close(fd)!=0||rename(temp,record)!=0){int e=errno;unlink(temp);errno=e;return -1;}
    return sync_parent_path(record);
}

static int recover_staged_temporary(const char *active, const char *staged)
{
    char temporary[4096],stage_content[8192],temp_content[8192],active_content[8192];
    struct stat stage_stat,temp_stat,active_stat;int stage_len,temp_len,active_len,n;
    n=snprintf(temporary,sizeof(temporary),"%s.p008-stage",active);if(n<0||(size_t)n>=sizeof(temporary))return -1;
    stage_len=read_regular(staged,stage_content,sizeof(stage_content),&stage_stat);if(stage_len<0)return -1;
    temp_len=read_regular(temporary,temp_content,sizeof(temp_content),&temp_stat);
    if(temp_len<0&&errno==ENOENT)return 0;
    if(temp_len>=0){
        if(temp_stat.st_uid!=stage_stat.st_uid||temp_stat.st_gid!=stage_stat.st_gid||
           ((temp_stat.st_mode&07777)!=0600&&(temp_stat.st_mode&07777)!=0644)||
           temp_len>stage_len||memcmp(temp_content,stage_content,(size_t)temp_len)!=0)return -1;
        return unlink_sync(temporary);
    }
    if(errno!=EPERM)return -1;
    /* linkat may have completed immediately before a crash. Remove the second
     * link only when both fixed paths identify the exact staged bytes. */
    active_len=read_regular_links(active,active_content,sizeof(active_content),&active_stat,2);
    temp_len=read_regular_links(temporary,temp_content,sizeof(temp_content),&temp_stat,2);
    if(active_len<0||temp_len<0||active_stat.st_dev!=temp_stat.st_dev||active_stat.st_ino!=temp_stat.st_ino||
       active_stat.st_uid!=stage_stat.st_uid||active_stat.st_gid!=stage_stat.st_gid||
       (active_stat.st_mode&07777)!=0644||active_len!=stage_len||memcmp(active_content,stage_content,(size_t)stage_len)!=0||
       temp_len!=active_len||memcmp(temp_content,active_content,(size_t)active_len)!=0)return -1;
    return unlink_sync(temporary);
}

static int read_record(const char *record, char *state, size_t cap, int fixture, int journal)
{
    char b[512]; struct stat st;uid_t uid;gid_t gid; int n=read_regular(record,b,sizeof(b),&st); const char *p;
    if(n<0)return errno==ENOENT?0:-1;
    if(service_identity(fixture,&uid,&gid)!=0||st.st_uid!=uid||st.st_gid!=gid||
       (st.st_mode&07777)!=0600 || strncmp(b,"ios-unsandboxed-service\nschema_version=1\nlabel=" LABEL "\nstate=",sizeof("ios-unsandboxed-service\nschema_version=1\nlabel=" LABEL "\nstate=")-1)!=0)return -1;
    p=strstr(b,"\nstate=")+7; if(strchr(p,'\n')==NULL||strlen(p)>=cap||strchr(p,'\n')[1]!='\0')return -1;
    strcpy(state,p);state[strlen(state)-1]='\0';
    if(strcmp(state,"registering")&&strcmp(state,"registered")&&strcmp(state,"stopping")&&strcmp(state,"unregistering")&&
       (strcmp(state,"starting")||!journal))return -1;
    return 1;
}

static int ipc_responsive(const char *root)
{
    char socket_path[4096]; struct sockaddr_un address; unsigned char request[20]={0}, response[20], payload[6];
    int fd, result=0; ssize_t n;
    if(path_join(socket_path,sizeof(socket_path),root,"/var/run/ios-unsandboxedd.sock")!=0)return 0;
    if(strlen(socket_path)>=sizeof(address.sun_path))return 0;
    fd=socket(AF_UNIX,SOCK_STREAM,0);if(fd<0)return 0;
    memset(&address,0,sizeof(address));address.sun_family=AF_UNIX;strcpy(address.sun_path,socket_path);
    {struct timeval timeout={0,250000};(void)setsockopt(fd,SOL_SOCKET,SO_RCVTIMEO,&timeout,sizeof(timeout));(void)setsockopt(fd,SOL_SOCKET,SO_SNDTIMEO,&timeout,sizeof(timeout));}
    if(connect(fd,(struct sockaddr *)&address,sizeof(address))!=0)goto done;
    memcpy(request,"IUIP",4);request[5]=1;request[7]=1;request[11]=1;
    {size_t sent=0;while(sent<sizeof(request)){n=send(fd,request+sent,sizeof(request)-sent,0);if(n<=0)goto done;sent+=(size_t)n;}}
    {size_t got=0;while(got<sizeof(response)){n=recv(fd,response+got,sizeof(response)-got,0);if(n<=0)goto done;got+=(size_t)n;}}
    if(memcmp(response,"IUIP",4)==0&&response[4]==0&&response[5]==1&&response[6]==0x80&&response[7]==1&&
       response[8]==0&&response[9]==0&&response[10]==0&&response[11]==1&&response[12]==0&&response[13]==0&&response[14]==0&&response[15]==6&&
       response[16]==0&&response[17]==0&&response[18]==0&&response[19]==0){
        size_t got=0;while(got<sizeof(payload)){n=recv(fd,payload+got,sizeof(payload)-got,0);if(n<=0)goto done;got+=(size_t)n;}
        if(payload[0]==5&&memcmp(payload+1,"0.1.0",5)==0)result=1;
    }
done: close(fd);return result;
}

static int wait_ipc(const char *root, int expected)
{
    struct timespec start,now; (void)clock_gettime(CLOCK_MONOTONIC,&start);
    for(;;){int ready=ipc_responsive(root);if(ready==expected)return 0;(void)clock_gettime(CLOCK_MONOTONIC,&now);if(now.tv_sec-start.tv_sec>=TIMEOUT_SECONDS)return -1;
        {struct timespec pause={0,100000000L};(void)nanosleep(&pause,NULL);}}
}

static int wait_process_stopped(const char *root, int fixture)
{
    struct timespec start,now;(void)clock_gettime(CLOCK_MONOTONIC,&start);
    for(;;){int process=PROCESS_UNKNOWN;int job=query_launchd(root,fixture,&process);if(job==JOB_ABSENT||(job==JOB_LOADED&&process==PROCESS_STOPPED))return 0;
        (void)clock_gettime(CLOCK_MONOTONIC,&now);if(now.tv_sec-start.tv_sec>=TIMEOUT_SECONDS)return -1;
        {struct timespec pause={0,100000000L};(void)nanosleep(&pause,NULL);}}
}

int iu_service_lifecycle_run(const char *root, int fixture, enum iu_service_action action,
                             int apply, int confirmed, int acknowledge_run_at_load,
                             int installation_valid, int daemon_valid, int template_valid)
{
    char staged[4096],active[4096],record[4096],journal[4096],registered[64]="absent",journal_stage[64]="";
    int active_exists=0,job_exit=0,job=JOB_UNKNOWN,process=PROCESS_UNKNOWN,journal_state;
    if(path_join(staged,sizeof(staged),root,STAGED)||path_join(active,sizeof(active),root,ACTIVE)||
       path_join(record,sizeof(record),root,RECORD)||path_join(journal,sizeof(journal),root,JOURNAL))return 2;
    if(!fixture && geteuid()!=0){fprintf(stderr,"service: effective UID 0 is required\n");return 3;}
    if(installation_valid!=1){
        if(action==IU_SERVICE_PLAN||action==IU_SERVICE_STATUS){
            struct stat active_stat;int active_state=lstat(active,&active_stat);int active_errno=errno;job=query_launchd(root,fixture,&process);
            printf("Installation manifest: %s\nDaemon executable: invalid or unavailable\nStaged plist: invalid or unavailable\nActive plist: %s\nLaunchd query: %s\nRegistration record: unverified\nDaemon process: %s\nIPC responsiveness: %s\nAmethyst compatibility: UNKNOWN\nStartup/signing eligibility: UNKNOWN\nExecution activation: disabled\n",
                   installation_valid==0?"absent":"invalid",active_state==0?"present but unverified":active_errno==ENOENT?"absent":"unavailable",job==JOB_LOADED?"job reported loaded":job==JOB_ABSENT?"job absent":"unavailable or unsupported",process==PROCESS_RUNNING?"running (launchctl PID column)":process==PROCESS_STOPPED?"not running (launchctl PID column)":"UNKNOWN",ipc_responsive(root)?"responsive (PING v1)":"unavailable or unresponsive");
            if(action==IU_SERVICE_PLAN)puts("Plan: install or repair the project package first; no service changes are planned until ownership and integrity verify.");
            return 0;
        }
        fprintf(stderr,"service: P007 installation manifest or disabled state is invalid\n");return 3;
    }
    {char template_content[8192];struct stat template_stat;int template_length=read_regular(staged,template_content,sizeof(template_content),&template_stat);struct group *wheel=getgrnam("wheel");gid_t expected_gid=fixture?getegid():(wheel?wheel->gr_gid:(gid_t)-1);
     if(template_length<0||template_stat.st_uid!=(fixture?geteuid():0)||template_stat.st_gid!=expected_gid||(template_stat.st_mode&07777)!=0600){fprintf(stderr,"service: staged plist owner, mode, or type is unsafe\n");return 3;}
     if(verify_active_parent(root,fixture,fixture?geteuid():0,expected_gid)!=0){fprintf(stderr,"service: active LaunchDaemons directory is missing, foreign, or unsafe\n");return 3;}}
    if(read_record(record,registered,sizeof(registered),fixture,0)<0){fprintf(stderr,"service: registration record is corrupt or unsafe\n");return 3;}
    journal_state=read_record(journal,journal_stage,sizeof(journal_stage),fixture,1);
    if(journal_state<0){fprintf(stderr,"service: P008 journal is corrupt or unsafe; preserve it for review\n");return 3;}
    if(apply&&action!=IU_SERVICE_RECOVER&&journal_state!=0){fprintf(stderr,"service: an incomplete lifecycle journal exists; run service recover --apply --confirm first\n");return 3;}
    job=query_launchd(root,fixture,&process);
    if(action==IU_SERVICE_PLAN||action==IU_SERVICE_STATUS){
        printf("Installation manifest: valid\nDaemon executable: %s\nStaged plist: %s\n",daemon_valid?"verified":"invalid",template_valid?"verified":"invalid");
        if(verified_active(active,staged,&active_exists)==0)printf("Active plist: %s\n",active_exists?"verified project copy":"absent");else printf("Active plist: foreign or unsafe\n");
        printf("Launchd query: %s\nRegistration record: %s\nP008 journal: %s\nDaemon process: %s\nIPC responsiveness: %s\nAmethyst compatibility: UNKNOWN\nStartup/signing eligibility: UNKNOWN\nExecution activation: disabled\n",job==JOB_LOADED?"job reported loaded":job==JOB_ABSENT?"job absent":"unavailable or unsupported",registered,journal_state==0?"absent":journal_stage,process==PROCESS_RUNNING?"running (launchctl PID column)":process==PROCESS_STOPPED?"not running (launchctl PID column)":"UNKNOWN",ipc_responsive(root)?"responsive (PING v1)":"unavailable or unresponsive");
        if(action==IU_SERVICE_PLAN){puts("Plan is read-only. Registration may start the daemon because RunAtLoad=true; iOS 12.5.7 launchctl syntax and startup eligibility are unverified.");if(journal_state!=0)puts("Recovery required: reconcile verified filesystem and launchd state with service recover --apply --confirm.");}
        return 0;
    }
    if(!apply){
        if(action==IU_SERVICE_RECOVER){if(journal_state==0)puts("Recovery plan: no P008 journal; no changes.");else printf("Recovery plan: inspect and reconcile the verified service state for stage %s; no journal command will be replayed.\n",journal_stage);}
        else printf("Service %s plan only; repeat with --apply --confirm to mutate.\n",action==IU_SERVICE_REGISTER?"register":action==IU_SERVICE_START?"start":action==IU_SERVICE_STOP?"stop":"unregister");
        return 0;
    }
    if(!confirmed){fprintf(stderr,"service: mutation requires explicit --confirm\n");return 2;}
    if(!daemon_valid||!template_valid){fprintf(stderr,"service: verified daemon and staged plist are required\n");return 3;}
        if(action==IU_SERVICE_REGISTER){
        if(!acknowledge_run_at_load){fprintf(stderr,"service: registration may start the daemon; pass --acknowledge-run-at-load to accept that behavior\n");return 2;}
        if(verified_active(active,staged,&active_exists)!=0){fprintf(stderr,"service: active plist is foreign or modified; preserved\n");return 3;}
        if(active_exists&&job==JOB_LOADED){puts("Service already registered; no change.");return 0;}
        if(active_exists){fprintf(stderr,"service: active project plist exists but launchd state is ambiguous; recover required\n");return 3;}
        if(job==JOB_LOADED){fprintf(stderr,"service: launchd reports label loaded without verified active plist; collision refused\n");return 3;}
        if(job!=JOB_ABSENT){fprintf(stderr,"service: launchd state is unavailable or unsupported; registration refused\n");return 3;}
        {struct stat template_stat;char template_content[8192];(void)read_regular(staged,template_content,sizeof(template_content),&template_stat);
         if(ensure_log_directory(root,fixture,fixture?geteuid():0,template_stat.st_gid)!=0){fprintf(stderr,"service: required project log directory is missing or unsafe\n");return 3;}}
        if(write_record(journal,"registering",fixture)!=0||write_record(record,"registering",fixture)!=0){perror("service: write registration journal");return 3;}
        /* Write and sync a same-directory stage, then link without replacement. */
        {char content[8192],temporary[4096];int n,fd;struct stat sst;int len=snprintf(temporary,sizeof(temporary),"%s.p008-stage",active);
         if(len<0||(size_t)len>=sizeof(temporary))return 3;
         n=read_regular(staged,content,sizeof(content),&sst);if(n<0)return 3;
         fd=open(temporary,O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0600);if(fd<0){perror("service: active staging collision");return 3;}
         if(write(fd,content,(size_t)n)!=n||fchown(fd,sst.st_uid,sst.st_gid)!=0||fchmod(fd,0644)!=0||fsync(fd)!=0){int e=errno;close(fd);unlink(temporary);errno=e;perror("service: stage active plist");return 3;}
         if(close(fd)!=0||link(temporary,active)!=0){int e=errno;unlink(temporary);errno=e;perror("service: activate staged plist");return 3;}
         if(unlink_sync(temporary)!=0||sync_parent_path(active)!=0){perror("service: synchronize active plist");return 3;}}
        if(run_launchctl(root,fixture,"load",active,&job_exit,NULL,0)!=0||job_exit!=0){fprintf(stderr,"service: launchctl load failed or timed out; journal retained for recovery\n");return 3;}
        job=query_launchd(root,fixture,&process);if(job!=JOB_LOADED){fprintf(stderr,"service: launchctl accepted load but the exact label was not verifiably loaded; journal retained\n");return 3;}
        if(write_record(record,"registered",fixture)!=0||unlink_sync(journal)!=0){fprintf(stderr,"service: registration accepted but record update failed; recover required\n");return 3;}
        puts("Launchctl accepted load; RunAtLoad may have started the service. Process and IPC readiness remain unverified.");return 0;
    }
    if(action==IU_SERVICE_START){
        if(!active_exists&&verified_active(active,staged,&active_exists)!=0)return 3;
        if(!active_exists){fprintf(stderr,"service: project job is not registered\n");return 3;}
        if(job!=JOB_LOADED){fprintf(stderr,"service: job is not verifiably registered\n");return 3;}
        if(write_record(journal,"starting",fixture)!=0)return 3;
        if(run_launchctl(root,fixture,"start",LABEL,&job_exit,NULL,0)!=0||job_exit!=0)return 3;
        if(wait_ipc(root,1)!=0){fprintf(stderr,"service: launchctl accepted start, but bounded IPC readiness failed\n");return 3;}
        job=query_launchd(root,fixture,&process);if(job!=JOB_LOADED||process!=PROCESS_RUNNING){fprintf(stderr,"service: IPC responded but launchd process state is not verifiably running\n");return 3;}
        if(unlink_sync(journal)!=0)return 3;
        puts("Launchctl accepted start and the daemon answered the bounded IPC PING v1 readiness check.");return 0;
    }
    if(action==IU_SERVICE_STOP||action==IU_SERVICE_UNREGISTER){
        if(verified_active(active,staged,&active_exists)!=0||!active_exists){fprintf(stderr,"service: exact active plist ownership is not verified; preserved\n");return 3;}
        if(write_record(journal,action==IU_SERVICE_STOP?"stopping":"unregistering",fixture)!=0||write_record(record,action==IU_SERVICE_STOP?"stopping":"unregistering",fixture)!=0)return 3;
        if(action==IU_SERVICE_STOP){
            if(run_launchctl(root,fixture,"stop",LABEL,&job_exit,NULL,0)!=0||job_exit!=0){fprintf(stderr,"service: stop failed; cleanup refused\n");return 3;}
            if(wait_ipc(root,0)!=0||wait_process_stopped(root,fixture)!=0){fprintf(stderr,"service: daemon IPC or launchd PID remained active after stop; cleanup refused\n");return 3;}
            if(write_record(record,"registered",fixture)!=0)return 3;
        } else {
            /* unload stops only this job and prevents a stop-triggered restart
             * before the active plist is removed. */
            if(run_launchctl(root,fixture,"unload",active,&job_exit,NULL,0)!=0||job_exit!=0){fprintf(stderr,"service: unload failed; active plist preserved\n");return 3;}
            if(query_launchd(root,fixture,&process)!=JOB_ABSENT){fprintf(stderr,"service: unload did not verifiably remove the exact label; active plist preserved\n");return 3;}
            if(wait_ipc(root,0)!=0){fprintf(stderr,"service: daemon IPC remains responsive after unload; active plist preserved\n");return 3;}
            if(unlink_sync(active)!=0||unlink_sync(record)!=0)return 3;}
        if(unlink_sync(journal)!=0)return 3;
        puts(action==IU_SERVICE_STOP?"Project service stop was accepted; launchd reports no process and project IPC is unresponsive.":"Project service was unloaded and its verified active plist removed; unrelated jobs were not addressed.");return 0;
    }
    if(action==IU_SERVICE_RECOVER){
        if(journal_state==0){puts("No P008 transaction journal; no recovery changes.");return 0;}
        if(recover_staged_temporary(active,staged)!=0){fprintf(stderr,"service: staged activation file is ambiguous or modified; preserved\n");return 3;}
        if(verified_active(active,staged,&active_exists)!=0)return 3;
        if(job==JOB_UNKNOWN){fprintf(stderr,"service: launchd state is unavailable or unsupported; journal preserved for manual review\n");return 3;}
        if(active_exists&&job==JOB_ABSENT){
            /* Only registration and unregister journals authorize removing
             * the active file after launchd confirms the label absent. */
            if(strcmp(journal_stage,"registering")&&strcmp(journal_stage,"unregistering")){fprintf(stderr,"service: launchd is absent during a non-removal operation; manual review required\n");return 3;}
            if(wait_ipc(root,0)!=0){fprintf(stderr,"service: project IPC remains responsive while launchd reports absent; manual review required\n");return 3;}
            if(unlink_sync(active)!=0||unlink_sync(record)!=0)return 3;
            active_exists=0;
        }
        if(active_exists&&job==JOB_LOADED){if(write_record(record,"registered",fixture)!=0)return 3;}
        if(!active_exists&&job==JOB_LOADED){fprintf(stderr,"service: launchd reports project label loaded without active plist; refusing to infer or modify job\n");return 3;}
        if(!active_exists&&strcmp(journal_stage,"registering")&&strcmp(journal_stage,"unregistering")){fprintf(stderr,"service: active plist is absent during a non-removal operation; manual review required\n");return 3;}
        if(!active_exists){if(unlink_sync(record)!=0&&errno!=ENOENT)return 3;}
        if(unlink_sync(journal)!=0&&errno!=ENOENT)return 3;
        puts("Recovery reconciled verified plist and record presence. No command was replayed.");return 0;
    }
    return 2;
}
