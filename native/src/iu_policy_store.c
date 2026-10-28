#define _GNU_SOURCE 1
#define _DARWIN_C_SOURCE 1
#include "iu_policy_store.h"
#include <errno.h>
#include <dirent.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static int overlap(const char *a, const char *b) {
    size_t n = strlen(a); return strncmp(a,b,n)==0 && (b[n]=='\0' || b[n]=='/');
}
int iu_policy_scope_syntax(const char *p) {
    const size_t base = sizeof(IU_POLICY_SCOPE_BASE)-1U;
    size_t n, start;
    if (!p || (n=strlen(p)) <= base || n >= IU_POLICY_PATH_CAPACITY || strncmp(p,IU_POLICY_SCOPE_BASE,base)) return 0;
    if (p[n-1]=='/') return 0;
    start=1;
    for (size_t i=1;i<=n;i++) {
        unsigned char c=(unsigned char)p[i];
        if (i==n || c=='/') {
            size_t k=i-start;
            if (!k || (k==1 && p[start]=='.') || (k==2 && p[start]=='.' && p[start+1]=='.')) return 0;
            start=i+1;
        } else if (!((c>='a'&&c<='z')||(c>='A'&&c<='Z')||(c>='0'&&c<='9')||c=='.'||c=='_'||c=='-')) return 0;
    }
    return 1;
}
static int valid(const struct iu_policy_store *s) {
    if (s->count>IU_POLICY_MAX_DIRECTORIES) return 0;
    for (unsigned i=0;i<s->count;i++) {
        if (!iu_policy_scope_syntax(s->scopes[i]) || !s->inodes[i]) return 0;
        for (unsigned j=0;j<i;j++) if (overlap(s->scopes[j],s->scopes[i]) || overlap(s->scopes[i],s->scopes[j])) return 0;
        if (i && strcmp(s->scopes[i-1],s->scopes[i])>=0) return 0;
    }
    return 1;
}
int iu_policy_store_encode(const struct iu_policy_store *s,char *out,size_t cap,size_t *len) {
    static const char hex[]="0123456789abcdef";
    int n; size_t pos;
    if (!s||!out||!len||!valid(s)) return -1;
    n=snprintf(out,cap,"ios-unsandboxed-execution-policy\nschema_version=1\nmode=preview-only\nscope_count=%u\n",s->count);
    if(n<0||(size_t)n>=cap)return -1;
    pos=(size_t)n;
    for(unsigned i=0;i<s->count;i++) {
        n=snprintf(out+pos,cap-pos,"scope_%u=",i); if(n<0||(size_t)n>=cap-pos)return -1; pos+=(size_t)n;
        for(const unsigned char *p=(const unsigned char *)s->scopes[i];*p;p++) { if(pos+3>=cap)return -1; out[pos++]=hex[*p>>4];out[pos++]=hex[*p&15]; }
        n=snprintf(out+pos,cap-pos,"|%" PRIu64 "|%" PRIu64 "\n",s->devices[i],s->inodes[i]);
        if(n<0||(size_t)n>=cap-pos)return -1;
        pos+=(size_t)n;
    }
    *len=pos; return 0;
}
static int unhex(char c) { if(c>='0'&&c<='9')return c-'0'; if(c>='a'&&c<='f')return c-'a'+10; return -1; }
static void parse(char *buf,size_t len,struct iu_policy_store *s) {
    static const char header[]="ios-unsandboxed-execution-policy\nschema_version=";
    char *p,*end; unsigned long version,count; char canonical[IU_POLICY_STORE_MAX_BYTES+1U]; size_t encoded;
    s->state=IU_STORE_CORRUPT;
    if(!len || buf[len-1]!='\n' || memchr(buf,'\0',len) || len<sizeof(header)-1 || memcmp(buf,header,sizeof(header)-1))return;
    buf[len]='\0'; p=buf+sizeof(header)-1;
    if(*p<'1'||*p>'9')return;
    errno=0; version=strtoul(p,&end,10); if(errno||end==p||*end!='\n'||version>UINT32_MAX)return;
    s->schema=(unsigned)version; if(version!=1){s->state=IU_STORE_UNSUPPORTED;return;}
    p=end+1; if(strncmp(p,"mode=preview-only\nscope_count=",30)!=0)return; p+=30;
    if(*p<'0'||*p>'8')return;
    count=(unsigned long)(*p++-'0'); if(*p++!='\n')return; s->count=(unsigned)count;
    for(unsigned i=0;i<s->count;i++) {
        char prefix[16]; size_t j=0; int k=snprintf(prefix,sizeof(prefix),"scope_%u=",i);
        if(k<0||strncmp(p,prefix,(size_t)k))return;
        p+=k;
        while(*p!='|' && *p!='\n' && *p!='\0') { int a,b; if(!p[1] || (a=unhex(p[0]))<0 || (b=unhex(p[1]))<0 || j+1>=IU_POLICY_PATH_CAPACITY)return; s->scopes[i][j++]=(char)((a<<4)|b); if(!s->scopes[i][j-1])return; p+=2; }
        if(*p++!='|')return;
        s->scopes[i][j]='\0';
        if(*p<'0'||*p>'9')return;
        errno=0; s->devices[i]=strtoull(p,&end,10); if(errno||end==p||*end!='|')return; p=end+1;
        if(*p<'0'||*p>'9')return;
        errno=0; s->inodes[i]=strtoull(p,&end,10); if(errno||end==p||*end!='\n')return; p=end+1;
    }
    if(*p || !valid(s) || iu_policy_store_encode(s,canonical,sizeof(canonical),&encoded)!=0 || encoded!=len || memcmp(buf,canonical,len))return;
    s->state=IU_STORE_VALID;
}
#if defined(__APPLE__)
#define IU_MTIME_NS(s) ((s)->st_mtimespec.tv_nsec)
#define IU_CTIME_NS(s) ((s)->st_ctimespec.tv_nsec)
#else
#define IU_MTIME_NS(s) ((s)->st_mtim.tv_nsec)
#define IU_CTIME_NS(s) ((s)->st_ctim.tv_nsec)
#endif
static int same(const struct stat *a,const struct stat *b) {
    return a->st_dev==b->st_dev && a->st_ino==b->st_ino && a->st_mode==b->st_mode && a->st_uid==b->st_uid && a->st_gid==b->st_gid && a->st_nlink==b->st_nlink && a->st_size==b->st_size && a->st_mtime==b->st_mtime && IU_MTIME_NS(a)==IU_MTIME_NS(b) && a->st_ctime==b->st_ctime && IU_CTIME_NS(a)==IU_CTIME_NS(b);
}
int iu_policy_store_load(int dir,uid_t uid,gid_t gid,struct iu_policy_store *s) {
    struct stat d,a,b,path; char buf[IU_POLICY_STORE_MAX_BYTES+1U]; size_t n=0; int fd;
    if(!s)return -1;
    memset(s,0,sizeof(*s)); s->state=IU_STORE_IO_ERROR;
    if(dir<0){s->state=IU_STORE_MISSING;return 0;}
    if(fstat(dir,&d)!=0)return 0;
    if(!S_ISDIR(d.st_mode)||d.st_uid!=uid||d.st_gid!=gid||(d.st_mode&07777)!=0700){s->state=IU_STORE_UNSAFE;return 0;}
    fd=openat(dir,"execution-policy",O_RDONLY|O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC);
    if(fd<0){s->state=errno==ENOENT?IU_STORE_MISSING:errno==ELOOP?IU_STORE_UNSAFE:IU_STORE_IO_ERROR;return 0;}
    if(fstat(fd,&a)!=0){close(fd);return 0;}
    if(!S_ISREG(a.st_mode)||a.st_uid!=uid||a.st_gid!=gid||(a.st_mode&07777)!=0600||a.st_nlink!=1||a.st_size<0||(uint64_t)a.st_size>IU_POLICY_STORE_MAX_BYTES){s->state=IU_STORE_UNSAFE;close(fd);return 0;}
    while(n<IU_POLICY_STORE_MAX_BYTES){ssize_t r=read(fd,buf+n,IU_POLICY_STORE_MAX_BYTES-n);if(r>0){n+=(size_t)r;continue;}if(r==0)break;if(errno==EINTR)continue;close(fd);return 0;}
    if(fstat(fd,&b)!=0||fstatat(dir,"execution-policy",&path,AT_SYMLINK_NOFOLLOW)!=0){close(fd);return 0;}
    close(fd); if(!same(&a,&b)||!same(&a,&path)||(uint64_t)n!=(uint64_t)a.st_size){s->state=IU_STORE_UNSAFE;return 0;}
    parse(buf,n,s);return 0;
}
int iu_policy_scope_inspect(int rootfd,const char *path,uid_t uid,gid_t gid,struct iu_policy_directory_v1 *out,uint64_t *device,uint64_t *inode,int require_empty) {
    char copy[IU_POLICY_PATH_CAPACITY],*save=NULL,*part; int fd,next; struct stat a,b;
    if(!iu_policy_scope_syntax(path) || rootfd<0)return -1;
    fd=dup(rootfd); if(fd<0)return -1;
    if(fstat(fd,&a)!=0 || !S_ISDIR(a.st_mode) || a.st_uid!=uid || a.st_gid!=gid || (a.st_mode&0022)){close(fd);return -1;}
    strcpy(copy,path+1);part=strtok_r(copy,"/",&save);
    while(part){
        if(fstatat(fd,part,&a,AT_SYMLINK_NOFOLLOW)!=0 || !S_ISDIR(a.st_mode) || a.st_uid!=uid || a.st_gid!=gid || (a.st_mode&0022) || (a.st_mode&0500)!=0500){close(fd);return -1;}
        next=openat(fd,part,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC); if(next<0){close(fd);return -1;}
        if(fstat(next,&b)!=0 || !same(&a,&b)){close(next);close(fd);return -1;} close(fd);fd=next;part=strtok_r(NULL,"/",&save);
    }
    if(require_empty){
        int copyfd=dup(fd); DIR *dir; struct dirent *entry; int nonempty=0;
        if(copyfd<0){close(fd);return -1;}
        dir=fdopendir(copyfd);if(!dir){close(copyfd);close(fd);return -1;}
        errno=0; while((entry=readdir(dir))!=NULL){if(strcmp(entry->d_name,".") && strcmp(entry->d_name,"..")){nonempty=1;break;}}
        if(errno!=0)nonempty=1;
        closedir(dir);if(nonempty){close(fd);return -1;}
    }
    if(out){memset(out,0,sizeof(*out));out->path_length=(uint32_t)strlen(path);strcpy(out->path,path);out->owner_uid=(uint32_t)uid;out->mode=(uint32_t)b.st_mode;out->file_type=IU_POLICY_FILE_DIRECTORY;out->metadata_verified=1;}
    if(device)*device=(uint64_t)b.st_dev;
    if(inode)*inode=(uint64_t)b.st_ino;
    close(fd);return 0;
}
const char *iu_policy_store_state_name(unsigned s) {
    switch(s){case IU_STORE_MISSING:return "missing";case IU_STORE_VALID:return "valid";case IU_STORE_CORRUPT:return "corrupt";case IU_STORE_UNSAFE:return "unsafe";case IU_STORE_UNSUPPORTED:return "unsupported";default:return "I/O error";}
}
