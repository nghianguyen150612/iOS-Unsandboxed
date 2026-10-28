#define _GNU_SOURCE
#if defined(__APPLE__)
#define _DARWIN_C_SOURCE 1
#endif
#include "iu_ipc_server.h"
#include "iu_peer_auth.h"
#include "iu_ipc_protocol.h"
#include "iu_preflight.h"
#include "iu_amethyst_adapter.h"
#include "iu_service_state.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/file.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

#define IU_PROJECT_VERSION "0.1.0"
#define IU_IO_TIMEOUT_MS 2000
_Static_assert(sizeof(uid_t) <= sizeof(uint32_t), "IPC lifecycle UID field is 32-bit");
_Static_assert(sizeof(gid_t) <= sizeof(uint32_t), "IPC lifecycle GID field is 32-bit");
static volatile sig_atomic_t stopping;
static int production_lock = -1;
static void stop_signal(int signo) { (void)signo; stopping = 1; }

static uint16_t rd16(const unsigned char *p) { return (uint16_t)(((uint16_t)p[0] << 8) | p[1]); }
static uint32_t rd32(const unsigned char *p) { return ((uint32_t)p[0]<<24)|((uint32_t)p[1]<<16)|((uint32_t)p[2]<<8)|p[3]; }
static void wr16(unsigned char *p, uint16_t v) { p[0]=(unsigned char)(v>>8); p[1]=(unsigned char)v; }
static void wr32(unsigned char *p, uint32_t v) { p[0]=(unsigned char)(v>>24); p[1]=(unsigned char)(v>>16); p[2]=(unsigned char)(v>>8); p[3]=(unsigned char)v; }

static int transfer(int fd, unsigned char *buf, size_t len, int writing)
{
    size_t done=0;
    struct timespec deadline;
    if(clock_gettime(CLOCK_MONOTONIC,&deadline)!=0) return -1;
    deadline.tv_sec+=IU_IO_TIMEOUT_MS/1000;
    deadline.tv_nsec+=(long)(IU_IO_TIMEOUT_MS%1000)*1000000L;
    if(deadline.tv_nsec>=1000000000L) { deadline.tv_sec++; deadline.tv_nsec-=1000000000L; }
    while (done<len) {
        struct timespec now;
        if(clock_gettime(CLOCK_MONOTONIC,&now)!=0) return -1;
        long long remaining=(long long)(deadline.tv_sec-now.tv_sec)*1000LL+
                            (deadline.tv_nsec-now.tv_nsec)/1000000LL;
        if(remaining<=0) { errno=ETIMEDOUT; return -1; }
        struct pollfd pfd={fd, (short)(writing?POLLOUT:POLLIN), 0};
        int pr=poll(&pfd,1,(int)remaining);
        if (pr==0) { errno=ETIMEDOUT; return -1; }
        if (pr<0) { if(errno==EINTR) continue; return -1; }
        int flags=0;
#ifdef MSG_NOSIGNAL
        if(writing) flags=MSG_NOSIGNAL;
#endif
        ssize_t n=writing?send(fd,buf+done,len-done,flags):recv(fd,buf+done,len-done,0);
        if(n>0) { done+=(size_t)n; continue; }
        if(n==0) { errno=ECONNRESET; return -1; }
        if(errno==EINTR || errno==EAGAIN || errno==EWOULDBLOCK) continue;
        return -1;
    }
    return 0;
}

static void put_text(unsigned char *p, const char *s)
{
    size_t n=strlen(s); p[0]=(unsigned char)n; memcpy(p+1,s,n);
}

static uint32_t dispatch(uint16_t type, const struct iu_peer_identity *peer,
                         unsigned char *out, uint32_t *out_len,
                         const char *state_path, int test_mode)
{
    *out_len=0;
    if (type==IU_IPC_PING) {
        put_text(out,IU_PROJECT_VERSION); *out_len=1U+(uint32_t)strlen(IU_PROJECT_VERSION); return IU_IPC_SUCCESS;
    }
    if(type==IU_IPC_GET_STATUS) {
        /* daemon up, compat state, activation, interception, device acceptance */
        struct iu_preflight_result_v1 r;
        if(iu_preflight_detect_v1(&r)!=0) return IU_IPC_INTERNAL_ERROR;
        out[0]=1; wr32(out+1,r.compatibility_status); out[5]=0; out[6]=0; out[7]=0;
        *out_len=8; return IU_IPC_SUCCESS;
    }
    if(type==IU_IPC_GET_LIFECYCLE_STATUS) {
        struct iu_preflight_result_v1 preflight;
        struct iu_service_state_result_v1 state;
        uid_t expected_uid = test_mode ? geteuid() : 0;
        gid_t expected_gid = test_mode ? getegid() : 0;
        if(iu_preflight_detect_v1(&preflight)!=0) return IU_IPC_INTERNAL_ERROR;
        if(state_path==NULL) {
            memset(&state,0,sizeof(state));
            state.abi_version=IU_SERVICE_STATE_ABI_VERSION;
            state.struct_size=(uint32_t)sizeof(state);
            state.state_status=IU_SERVICE_STATE_DIRECTORY_MISSING;
            state.execution_activation=IU_EXECUTION_ACTIVATION_DISABLED;
        } else if(iu_service_state_load_v1(state_path,expected_uid,expected_gid,
                                           expected_uid,expected_gid,&state)!=0) {
            return IU_IPC_INTERNAL_ERROR;
        }
        /* New request ID preserves the exact P004 GET_STATUS v1 wire payload. */
        out[0]=1; /* lifecycle payload ABI */
        out[1]=(unsigned char)state.state_status;
        out[2]=(unsigned char)state.schema_supported;
        out[3]=(unsigned char)state.execution_activation;
        out[4]=(unsigned char)state.service_installation;
        out[5]=0; /* device acceptance: NOT TESTED */
        wr32(out+6,state.schema_version);
        wr32(out+10,preflight.compatibility_status);
        wr32(out+14,(uint32_t)peer->uid);
        wr32(out+18,(uint32_t)peer->gid);
        *out_len=22;
        return IU_IPC_SUCCESS;
    }
    if(type==IU_IPC_GET_PREFLIGHT) {
        struct iu_preflight_result_v1 r;
        if(iu_preflight_detect_v1(&r)!=0) return IU_IPC_INTERNAL_ERROR;
        /* Stable serialized subset: compat/system/arch/device-match/os-match (u32),
         * then four one-byte-length UTF-8 strings: machine, version, build, kernel. */
        wr32(out,r.compatibility_status); wr32(out+4,r.system_family); wr32(out+8,r.architecture);
        wr32(out+12,r.reference_device_match); wr32(out+16,r.reference_os_match);
        uint32_t pos=20; const struct iu_text_v1 *texts[]={&r.machine,&r.product_version,&r.system_build,&r.kernel_release};
        for(size_t i=0;i<4;i++) { uint32_t n=texts[i]->length; if(n>IU_PREFLIGHT_TEXT_CAPACITY-1) return IU_IPC_INTERNAL_ERROR; out[pos++]=(unsigned char)n; memcpy(out+pos,texts[i]->value,n); pos+=n; }
        *out_len=pos; return r.compatibility_status==IU_COMPAT_UNSUPPORTED_PLATFORM?IU_IPC_UNSUPPORTED_PLATFORM:
            r.compatibility_status==IU_COMPAT_UNVERIFIED?IU_IPC_PREFLIGHT_UNVERIFIED:IU_IPC_SUCCESS;
    }
    if(type==IU_IPC_GET_AMETHYST_ADAPTER) {
        struct iu_ame_probe_result_v1 adapter;
        if(iu_ame_adapter_probe_v1(&adapter)!=0) return IU_IPC_INTERNAL_ERROR;
        /* Additive read-only payload: ABI byte, six big-endian u32 values,
         * and the fixed pinned source revision. Component paths/hashes are
         * deliberately not exposed over IPC. */
        out[0]=1;
        wr32(out+1,adapter.compatibility);
        wr32(out+5,adapter.build_evidence);
        wr32(out+9,adapter.launchd_hook_evidence);
        wr32(out+13,adapter.base_hook_evidence);
        wr32(out+17,adapter.components[0].file_type);
        wr32(out+21,adapter.components[1].file_type);
        memcpy(out+25,adapter.source_revision.value,40);
        *out_len=65;
        return IU_IPC_SUCCESS;
    }
    if(type==IU_IPC_ENABLE || type==IU_IPC_DISABLE || type==IU_IPC_SET_POLICY) {
        if(!iu_peer_authorize_management(peer)) return IU_IPC_PERMISSION_DENIED;
        /* Root authentication is necessary, never sufficient to implement operations. */
        return IU_IPC_NOT_IMPLEMENTED;
    }
    if(type==IU_IPC_PREPARE_LAUNCH) return IU_IPC_PERMISSION_DENIED;
    return IU_IPC_NOT_IMPLEMENTED;
}

static void serve_client(int fd, const char *state_path, int test_mode)
{
    unsigned char h[IU_IPC_HEADER_SIZE], payload[IU_IPC_MAX_PAYLOAD], response[IU_IPC_MAX_PAYLOAD];
    struct iu_peer_identity peer;
    if(iu_peer_authenticate(fd,&peer)!=0 || !iu_peer_authorize_readonly(&peer)) return;
    if(transfer(fd,h,sizeof(h),0)!=0) return;
    uint16_t version=rd16(h+4), type=rd16(h+6); uint32_t id=rd32(h+8), n=rd32(h+12), req_status=rd32(h+16);
    uint32_t status=IU_IPC_INVALID_REQUEST, response_len=0;
    if(memcmp(h,IU_IPC_MAGIC,4)!=0 || n>IU_IPC_MAX_PAYLOAD || req_status!=0) goto respond;
    if(version!=IU_IPC_PROTOCOL_VERSION) { status=IU_IPC_UNSUPPORTED_VERSION; goto read_body; }
    if(n!=0) { if(transfer(fd,payload,n,0)!=0) return; }
    /* All supported v1 operations have empty request payloads. */
    if(n!=0) goto respond;
    {
        unsigned char extra;
        struct pollfd trailing_pfd={fd,POLLIN,0};
        int ready=poll(&trailing_pfd,1,0);
        if(ready>0 && (trailing_pfd.revents&POLLIN)!=0) {
            ssize_t trailing=recv(fd,&extra,1,MSG_PEEK);
            if(trailing>0) goto respond;
            if(trailing<0 && errno!=EAGAIN && errno!=EWOULDBLOCK && errno!=EINTR) return;
        }
        if(ready<0 && errno!=EINTR) return;
    }
    status=dispatch(type,&peer,response,&response_len,state_path,test_mode);
respond:
    memcpy(h,IU_IPC_MAGIC,4); wr16(h+4,IU_IPC_PROTOCOL_VERSION); wr16(h+6,(uint16_t)(type|IU_IPC_RESPONSE_BIT));
    wr32(h+8,id); wr32(h+12,response_len); wr32(h+16,status);
    if(transfer(fd,h,sizeof(h),1)==0 && response_len<=IU_IPC_MAX_PAYLOAD) (void)transfer(fd,response,response_len,1);
    return;
read_body:
    if(n!=0 && n<=IU_IPC_MAX_PAYLOAD && transfer(fd,payload,n,0)!=0) return;
    goto respond;
}

static int validate_parent(const char *path, int test_mode)
{
    char parent[sizeof(((struct sockaddr_un *)0)->sun_path)];
    char resolved[PATH_MAX];
    struct stat st; const char *slash=strrchr(path,'/');
    if(slash==NULL || slash==path) return -1;
    size_t n=(size_t)(slash-path); if(n>=sizeof(parent)) return -1; memcpy(parent,path,n); parent[n]='\0';
    if(test_mode && (strcmp(parent,"/var/run")==0 || realpath(parent,resolved)==NULL || strcmp(parent,resolved)!=0)) return -1;
    if(lstat(parent,&st)!=0 || !S_ISDIR(st.st_mode)) return -1;
    if((st.st_mode & (S_IWGRP|S_IWOTH))!=0) return -1;
    if(!test_mode && (st.st_uid!=0 || st.st_gid!=0 || geteuid()!=0)) return -1;
    if(test_mode && (st.st_uid!=geteuid() || st.st_gid!=getegid())) return -1;
    return 0;
}

static int setup_socket(const char *path, int test_mode, struct stat *owned)
{
    struct sockaddr_un addr; struct stat st, current; int fd=-1, lock=-1, have_owned=0;
    if(strlen(path)>=sizeof(addr.sun_path) || validate_parent(path,test_mode)!=0) { errno=EPERM; return -1; }
    if(!test_mode) {
        char lockpath[sizeof(addr.sun_path)];
        if(snprintf(lockpath,sizeof(lockpath),"%s.lock",path)>=(int)sizeof(lockpath)) { errno=ENAMETOOLONG; return -1; }
        lock=open(lockpath,O_CREAT|O_RDWR|O_NOFOLLOW|O_CLOEXEC,0600);
        if(lock<0 || fstat(lock,&st)!=0 || !S_ISREG(st.st_mode) || st.st_uid!=0 || st.st_gid!=0 || st.st_nlink!=1 ||
           (st.st_mode&07777)!=0600 || flock(lock,LOCK_EX|LOCK_NB)!=0) { if(lock>=0)close(lock); errno=EADDRINUSE; return -1; }
        production_lock=lock;
    }
    if(lstat(path,&st)==0) {
        if(!S_ISSOCK(st.st_mode) || st.st_uid!=(test_mode?geteuid():0) ||
           st.st_gid!=(test_mode?getegid():0)) { errno=EEXIST; goto fail; }
        int probe=socket(AF_UNIX,SOCK_STREAM,0); if(probe<0) goto fail;
        memset(&addr,0,sizeof(addr)); addr.sun_family=AF_UNIX; memcpy(addr.sun_path,path,strlen(path)+1);
        int cr=connect(probe,(struct sockaddr *)&addr,sizeof(addr)); int e=errno; close(probe);
        if(cr==0 || (e!=ECONNREFUSED && e!=ENOENT)) { errno=EADDRINUSE; goto fail; }
        if(lstat(path,&current)!=0 || !S_ISSOCK(current.st_mode) || current.st_dev!=st.st_dev ||
           current.st_ino!=st.st_ino || current.st_uid!=st.st_uid || current.st_gid!=st.st_gid) { errno=EAGAIN; goto fail; }
        if(unlink(path)!=0) goto fail;
    } else if(errno!=ENOENT) goto fail;
    fd=socket(AF_UNIX,SOCK_STREAM,0); if(fd<0) goto fail;
    memset(&addr,0,sizeof(addr)); addr.sun_family=AF_UNIX; memcpy(addr.sun_path,path,strlen(path)+1);
    mode_t old=umask(077); int br=bind(fd,(struct sockaddr *)&addr,sizeof(addr)); umask(old);
    if(br!=0) goto fail;
    if(lstat(path,owned)!=0 || !S_ISSOCK(owned->st_mode)) goto fail;
    if(owned->st_uid!=(test_mode?geteuid():0) || owned->st_gid!=(test_mode?getegid():0)) { errno=EPERM; goto fail; }
    have_owned=1;
    if(chmod(path,0600)!=0 || listen(fd,4)!=0) goto fail;
    return fd;
fail:
    if(fd>=0)close(fd);
    if(have_owned && lstat(path,&current)==0 && S_ISSOCK(current.st_mode) &&
       current.st_dev==owned->st_dev && current.st_ino==owned->st_ino &&
       current.st_uid==owned->st_uid && current.st_gid==owned->st_gid)
        (void)unlink(path);
    if(lock>=0)close(lock);
    production_lock=-1;
    return -1;
}

int iu_ipc_serve(const char *path, int test_mode, const char *state_path)
{
    struct stat owned, now; int fd; int exit_status=0; struct sigaction sa;
    if(test_mode && strcmp(path,"/var/run/ios-unsandboxedd.sock")==0) { fprintf(stderr,"ios-unsandboxedd: test socket may not use production path\n"); return -1; }
    if(!test_mode && geteuid()!=0) { fprintf(stderr,"ios-unsandboxedd: --serve requires effective uid 0\n"); return -1; }
    memset(&sa,0,sizeof(sa)); sa.sa_handler=stop_signal; sigemptyset(&sa.sa_mask);
    stopping=0;
    if(sigaction(SIGTERM,&sa,NULL)!=0 || sigaction(SIGINT,&sa,NULL)!=0) {
        perror("ios-unsandboxedd: signal setup");
        return -1;
    }
    fd=setup_socket(path,test_mode,&owned); if(fd<0) { perror("ios-unsandboxedd: socket setup"); return -1; }
    (void)fprintf(stderr,"ios-unsandboxedd: foreground read-only IPC ready; execution activation disabled.\n");
    while(!stopping) {
        struct pollfd pfd={fd,POLLIN,0}; int p=poll(&pfd,1,250);
        if(p<0) { if(errno==EINTR)continue; perror("ios-unsandboxedd: listener poll"); exit_status=-1; break; }
        if(p==0)continue;
        if((pfd.revents&POLLIN)==0) {
            if((pfd.revents&(POLLERR|POLLHUP|POLLNVAL))!=0) {
                errno=EIO; perror("ios-unsandboxedd: listener state"); exit_status=-1; break;
            }
            continue;
        }
        int client=accept(fd,NULL,NULL); if(client<0) { if(errno==EINTR || errno==EAGAIN || errno==EWOULDBLOCK)continue; perror("ios-unsandboxedd: accept"); exit_status=-1; break; }
        struct timeval tv={2,0}; (void)setsockopt(client,SOL_SOCKET,SO_RCVTIMEO,&tv,sizeof(tv)); (void)setsockopt(client,SOL_SOCKET,SO_SNDTIMEO,&tv,sizeof(tv));
#ifdef SO_NOSIGPIPE
        { int one=1; (void)setsockopt(client,SOL_SOCKET,SO_NOSIGPIPE,&one,sizeof(one)); }
#endif
        serve_client(client,state_path,test_mode); close(client);
    }
    close(fd);
    if(lstat(path,&now)==0 && S_ISSOCK(now.st_mode) && now.st_dev==owned.st_dev &&
       now.st_ino==owned.st_ino && now.st_uid==owned.st_uid && now.st_gid==owned.st_gid)
        (void)unlink(path);
    if(production_lock>=0) { close(production_lock); production_lock=-1; }
    return exit_status;
}
