#define _DARWIN_C_SOURCE 1
#define _GNU_SOURCE 1
#include "iu_service_state.h"
#include "iu_service_lifecycle.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <inttypes.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>
#include <arpa/inet.h>
#if defined(__APPLE__)
#include <sys/sysctl.h>
#endif

/*
 * P007 installer helper. All accepted names and destination paths are fixed
 * here; package and manifest fields are parsed as data and never evaluated.
 * Directory-relative O_NOFOLLOW opens and same-directory renames protect the
 * mutation boundary. A multi-directory deployment is journaled and recoverable,
 * but cannot be one atomic transaction across filesystems.
 */

#define FILE_COUNT 8
#define PACKAGE_FILE_COUNT 7
#define MAX_META_BYTES 32768
#define HASH_HEX 65

enum file_type { FILE_REGULAR = 1, FILE_SYMLINK = 2 };

struct file_spec {
    const char *destination;
    const char *package_path;
    const char *leaf;
    unsigned mode;
    enum file_type type;
    const char *link_target;
    int package_index;
};

static const struct file_spec FILES[FILE_COUNT] = {
    {"/usr/local/bin/ios-unsandboxed", "payload/bin/ios-unsandboxed", "ios-unsandboxed", 0755, FILE_REGULAR, NULL, 0},
    {"/usr/local/bin/iu", NULL, "iu", 0777, FILE_SYMLINK, "/usr/local/bin/ios-unsandboxed", -1},
    {"/usr/local/bin/ios-unsandboxedd", "payload/bin/ios-unsandboxedd", "ios-unsandboxedd", 0755, FILE_REGULAR, NULL, 1},
    {"/var/lib/ios-unsandboxed/manager.sh", "payload/share/manager.sh", "manager.sh", 0700, FILE_REGULAR, NULL, 2},
    {"/var/lib/ios-unsandboxed/installer-helper", "payload/share/installer-helper", "installer-helper", 0700, FILE_REGULAR, NULL, 3},
    {"/var/lib/ios-unsandboxed/paths.env", "payload/share/paths.env", "paths.env", 0600, FILE_REGULAR, NULL, 4},
    {"/var/lib/ios-unsandboxed/com.ios-unsandboxed.daemon.plist.inactive", "payload/share/com.ios-unsandboxed.daemon.plist", "com.ios-unsandboxed.daemon.plist.inactive", 0600, FILE_REGULAR, NULL, 6},
    {"/var/lib/ios-unsandboxed/install-state", NULL, "install-state", 0600, FILE_REGULAR, NULL, -1}
};

static const char *PACKAGE_PATHS[PACKAGE_FILE_COUNT] = {
    "payload/bin/ios-unsandboxed",
    "payload/bin/ios-unsandboxedd",
    "payload/share/manager.sh",
    "payload/share/installer-helper",
    "payload/share/paths.env",
    "payload/share/install-state.example",
    "payload/share/com.ios-unsandboxed.daemon.plist"
};
static const char *MACH_O_PATHS[3] = {
    "payload/bin/ios-unsandboxed",
    "payload/bin/ios-unsandboxedd",
    "payload/share/installer-helper"
};
static const unsigned PACKAGE_MODES[PACKAGE_FILE_COUNT] = {
    0755, 0755, 0700, 0700, 0600, 0600, 0600
};
static const char *SIGNING_VALUES[] = {
    "unsigned", "adhoc_signed", "signed_unverified",
    "signature_verification_passed", "unknown"
};

struct sha256_ctx {
    uint32_t h[8];
    uint64_t bits;
    uint8_t block[64];
    size_t used;
};

static uint32_t rotr32(uint32_t x, unsigned n) { return (x >> n) | (x << (32U - n)); }
static uint32_t load_be32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}
static uint32_t load_le32(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}
static void store_be32(uint8_t *p, uint32_t x)
{
    p[0] = (uint8_t)(x >> 24); p[1] = (uint8_t)(x >> 16);
    p[2] = (uint8_t)(x >> 8); p[3] = (uint8_t)x;
}

static void sha256_transform(struct sha256_ctx *ctx, const uint8_t *block)
{
    static const uint32_t k[64] = {
        0x428a2f98U,0x71374491U,0xb5c0fbcfU,0xe9b5dba5U,0x3956c25bU,0x59f111f1U,0x923f82a4U,0xab1c5ed5U,
        0xd807aa98U,0x12835b01U,0x243185beU,0x550c7dc3U,0x72be5d74U,0x80deb1feU,0x9bdc06a7U,0xc19bf174U,
        0xe49b69c1U,0xefbe4786U,0x0fc19dc6U,0x240ca1ccU,0x2de92c6fU,0x4a7484aaU,0x5cb0a9dcU,0x76f988daU,
        0x983e5152U,0xa831c66dU,0xb00327c8U,0xbf597fc7U,0xc6e00bf3U,0xd5a79147U,0x06ca6351U,0x14292967U,
        0x27b70a85U,0x2e1b2138U,0x4d2c6dfcU,0x53380d13U,0x650a7354U,0x766a0abbU,0x81c2c92eU,0x92722c85U,
        0xa2bfe8a1U,0xa81a664bU,0xc24b8b70U,0xc76c51a3U,0xd192e819U,0xd6990624U,0xf40e3585U,0x106aa070U,
        0x19a4c116U,0x1e376c08U,0x2748774cU,0x34b0bcb5U,0x391c0cb3U,0x4ed8aa4aU,0x5b9cca4fU,0x682e6ff3U,
        0x748f82eeU,0x78a5636fU,0x84c87814U,0x8cc70208U,0x90befffaU,0xa4506cebU,0xbef9a3f7U,0xc67178f2U
    };
    uint32_t w[64], a,b,c,d,e,f,g,h;
    size_t i;
    for (i = 0; i < 16; ++i) w[i] = load_be32(block + i * 4U);
    for (; i < 64; ++i) {
        uint32_t s0 = rotr32(w[i-15],7) ^ rotr32(w[i-15],18) ^ (w[i-15] >> 3);
        uint32_t s1 = rotr32(w[i-2],17) ^ rotr32(w[i-2],19) ^ (w[i-2] >> 10);
        w[i] = w[i-16] + s0 + w[i-7] + s1;
    }
    a=ctx->h[0]; b=ctx->h[1]; c=ctx->h[2]; d=ctx->h[3];
    e=ctx->h[4]; f=ctx->h[5]; g=ctx->h[6]; h=ctx->h[7];
    for (i = 0; i < 64; ++i) {
        uint32_t s1=rotr32(e,6)^rotr32(e,11)^rotr32(e,25), ch=(e&f)^(~e&g);
        uint32_t t1=h+s1+ch+k[i]+w[i];
        uint32_t s0=rotr32(a,2)^rotr32(a,13)^rotr32(a,22), maj=(a&b)^(a&c)^(b&c);
        uint32_t t2=s0+maj;
        h=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
    }
    ctx->h[0]+=a; ctx->h[1]+=b; ctx->h[2]+=c; ctx->h[3]+=d;
    ctx->h[4]+=e; ctx->h[5]+=f; ctx->h[6]+=g; ctx->h[7]+=h;
}
static void sha256_init(struct sha256_ctx *ctx)
{
    static const uint32_t init[8] = {0x6a09e667U,0xbb67ae85U,0x3c6ef372U,0xa54ff53aU,0x510e527fU,0x9b05688cU,0x1f83d9abU,0x5be0cd19U};
    memcpy(ctx->h, init, sizeof(init)); ctx->bits=0; ctx->used=0;
}
static void sha256_update(struct sha256_ctx *ctx, const uint8_t *data, size_t len)
{
    while (len > 0) {
        size_t take = 64U - ctx->used;
        if (take > len) take = len;
        memcpy(ctx->block + ctx->used, data, take);
        ctx->used += take; ctx->bits += (uint64_t)take * 8U;
        data += take; len -= take;
        if (ctx->used == 64U) { sha256_transform(ctx, ctx->block); ctx->used=0; }
    }
}
static void sha256_final(struct sha256_ctx *ctx, uint8_t out[32])
{
    uint64_t bits=ctx->bits;
    size_t i;
    ctx->block[ctx->used++]=0x80U;
    if (ctx->used > 56U) { memset(ctx->block+ctx->used,0,64U-ctx->used); sha256_transform(ctx,ctx->block); ctx->used=0; }
    memset(ctx->block+ctx->used,0,56U-ctx->used);
    for (i=0;i<8U;++i) ctx->block[63U-i]=(uint8_t)(bits>>(i*8U));
    sha256_transform(ctx,ctx->block);
    for (i=0;i<8U;++i) store_be32(out+i*4U,ctx->h[i]);
}
static void hash_hex(const uint8_t *bytes, size_t len, char output[HASH_HEX])
{
    static const char hex[]="0123456789abcdef";
    struct sha256_ctx ctx; uint8_t digest[32]; size_t i;
    sha256_init(&ctx); sha256_update(&ctx,bytes,len); sha256_final(&ctx,digest);
    for(i=0;i<32U;++i){output[i*2U]=hex[digest[i]>>4];output[i*2U+1U]=hex[digest[i]&15U];}
    output[64]='\0';
}
static int hash_fd(int fd, char output[HASH_HEX])
{
    struct sha256_ctx ctx; uint8_t buf[16384], digest[32]; ssize_t got; size_t i;
    if (lseek(fd,0,SEEK_SET)<0) return -1;
    sha256_init(&ctx);
    while ((got=read(fd,buf,sizeof(buf)))>0) sha256_update(&ctx,buf,(size_t)got);
    if(got<0) return -1;
    sha256_final(&ctx,digest);
    for(i=0;i<32U;++i){static const char hex[]="0123456789abcdef";output[i*2U]=hex[digest[i]>>4];output[i*2U+1U]=hex[digest[i]&15U];}
    output[64]='\0'; return 0;
}

struct manifest_entry { char hash[HASH_HEX]; uid_t uid; gid_t gid; unsigned mode; enum file_type type; };
struct manifest {
    char project_version[32];
    char package_generation[HASH_HEX];
    char backup_generation[80];
    char signing_status[48];
    struct manifest_entry files[FILE_COUNT];
};
struct package {
    int dirfd;
    char version[32];
    char signing[48];
    char signature_verification[32];
    char manifest_hash[HASH_HEX];
    char hashes[PACKAGE_FILE_COUNT][HASH_HEX];
};
struct transaction {
    char action[16];
    char recovery_generation[80];
    char target_generation[80];
    char staging_generation[80];
    char package_generation[HASH_HEX];
    char phase[32];
};
struct context {
    int fixture;
    char root[PATH_MAX];
    int rootfd, varlibfd, bindirfd, dataparentfd, datafd, backupsfd, stagingfd;
    uid_t uid; gid_t gid; gid_t wheel_gid;
    int lock_held, lockfd, data_created;
};
#if defined(IU_INSTALLER_TESTING)
static const char *test_interrupt_at;
static const char *test_active_action;
static unsigned test_commit_count;
static void maybe_interrupt(const char *phase)
{
    if(test_interrupt_at==NULL)return;
    if(strcmp(test_interrupt_at,phase)==0)_exit(86);
    if(strncmp(test_interrupt_at,"commit:",7)==0||strncmp(test_interrupt_at,"rollback:",9)==0){
        unsigned wanted=0;const char *number=strchr(test_interrupt_at,':');
        if(number!=NULL&&strcmp(test_interrupt_at,"commit:")!=0&&strcmp(test_interrupt_at,"rollback:")!=0){
            char *end=NULL;unsigned long parsed=strtoul(number+1,&end,10);
            if(end!=number+1&&*end=='\0'&&parsed>0&&parsed<=UINT_MAX)wanted=(unsigned)parsed;
        }
        if(wanted>0&&wanted==test_commit_count&&
           ((strncmp(test_interrupt_at,"rollback:",9)==0&&test_active_action&&strcmp(test_active_action,"rollback")==0)||
            (strncmp(test_interrupt_at,"commit:",7)==0&&test_active_action&&strcmp(test_active_action,"rollback")!=0)))_exit(86);
    }
}
#endif

static void fail(const char *message) { fprintf(stderr,"installer: %s\n",message); }
static int bad(const char *message) { fail(message); return 1; }
static int is_hex64(const char *s)
{
    size_t i; if(strlen(s)!=64U)return 0;
    for(i=0;i<64U;++i)if(!((s[i]>='0'&&s[i]<='9')||(s[i]>='a'&&s[i]<='f')))return 0;
    return 1;
}
static int safe_generation(const char *s)
{
    size_t i,n=strlen(s); if(n<5U||n>79U||s[0]!='g')return 0;
    for(i=1;i<n;++i)if(!((s[i]>='0'&&s[i]<='9')||s[i]=='-'))return 0;
    return 1;
}
static int safe_project_version(const char *s)
{
    size_t len=strlen(s);unsigned dots=0;int digit=0;unsigned long component=0;
    if(len==0||len>=32U)return 0;
    for(size_t i=0;i<len;++i){
        if(s[i]=='.'){if(!digit||dots>=2U)return 0;++dots;digit=0;component=0;continue;}
        if(s[i]<'0'||s[i]>'9')return 0;
        {unsigned value=(unsigned)(s[i]-'0');if(component>((unsigned long)UINT_MAX-value)/10UL)return 0;component=component*10UL+value;}
        digit=1;
    }
    return dots==2U&&digit;
}
static int known_signing_status(const char *status)
{
    for(size_t i=0;i<sizeof(SIGNING_VALUES)/sizeof(SIGNING_VALUES[0]);++i)
        if(strcmp(status,SIGNING_VALUES[i])==0)return 1;
    return 0;
}
static int valid_metadata_bytes(const char *text,size_t length)
{
    if(length==0||text[0]=='\n'||text[length-1]!='\n')return 0;
    for(size_t i=0;i<length;++i){unsigned char c=(unsigned char)text[i];if(c=='\n'){if(i>0&&text[i-1]=='\n')return 0;continue;}if(c<0x20U||c>0x7eU)return 0;}
    return 1;
}
static int mode_safe_dir(const struct stat *st)
{
    return S_ISDIR(st->st_mode) && (st->st_mode & 0022) == 0 && st->st_nlink >= 2;
}
static int mode_safe_package(const struct stat *st)
{
    return S_ISDIR(st->st_mode) && (st->st_mode & 0022) == 0;
}
static int stat_expected(const struct context *ctx, const struct stat *st)
{
    return st->st_uid==ctx->uid && st->st_gid==ctx->gid;
}
static int expected_mode(const struct context *ctx, const struct stat *st, unsigned mode)
{
    return stat_expected(ctx,st) && (st->st_mode&07777)==mode;
}

static int read_all_fd(int fd, char *buf, size_t cap, size_t *length)
{
    size_t used=0; ssize_t n;
    if(lseek(fd,0,SEEK_SET)<0)return -1;
    while(used<cap){n=read(fd,buf+used,cap-used);if(n>0){used+=(size_t)n;continue;}if(n==0)break;if(errno==EINTR)continue;return -1;}
    if(used==cap){char c;do{n=read(fd,&c,1);}while(n<0&&errno==EINTR);if(n!=0){errno=EFBIG;return -1;}}
    buf[used]='\0';*length=used;return 0;
}
static int read_named(int dirfd,const char *name,char *buf,size_t cap,size_t *len,mode_t required_mode,uid_t uid,gid_t gid)
{
    int fd; struct stat st;
    fd=openat(dirfd,name,O_RDONLY|O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC);
    if(fd<0)return -1;
    if(fstat(fd,&st)!=0||!S_ISREG(st.st_mode)||st.st_nlink!=1||st.st_uid!=uid||st.st_gid!=gid||
       (st.st_mode&07777)!=required_mode||st.st_size<0||(uint64_t)st.st_size>=cap){close(fd);errno=EPERM;return -1;}
    if(read_all_fd(fd,buf,cap-1,len)!=0){int saved=errno;close(fd);errno=saved;return -1;}
    close(fd);return 0;
}
static int write_all(int fd,const void *data,size_t length)
{
    const uint8_t *p=data;while(length){ssize_t n=write(fd,p,length);if(n>0){p+=(size_t)n;length-=(size_t)n;continue;}if(n<0&&errno==EINTR)continue;return -1;}return 0;
}
static int fsync_dir(int fd)
{
    if(fsync(fd)==0)return 0;
    /* Some iOS and older filesystems reject directory fsync. Do not suppress
     * ordinary errors; EINVAL/ENOTSUP are the documented portability limit. */
    if(errno==EINVAL||errno==ENOTSUP||errno==EOPNOTSUPP)return 0;
    return -1;
}

static int open_fixture_subdir(int rootfd,const char *path)
{
    char copy[PATH_MAX],*save=NULL,*part; int fd=dup(rootfd),next;
    if(fd<0||strlen(path)>=sizeof(copy)){if(fd>=0)close(fd);return -1;}
    strcpy(copy,path);part=strtok_r(copy,"/",&save);
    while(part){next=openat(fd,part,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);close(fd);if(next<0)return -1;fd=next;part=strtok_r(NULL,"/",&save);}
    return fd;
}
static int open_base_dirs(struct context *ctx)
{
    struct stat st;int localfd=-1,usrfd=-1;
    if(ctx->fixture){
        ctx->rootfd=open(ctx->root,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
        if(ctx->rootfd<0)return -1;
        ctx->varlibfd=open_fixture_subdir(ctx->rootfd,"var/lib");
        ctx->bindirfd=open_fixture_subdir(ctx->rootfd,"usr/local/bin");
        usrfd=open_fixture_subdir(ctx->rootfd,"usr");
        localfd=open_fixture_subdir(ctx->rootfd,"usr/local");
        ctx->dataparentfd=ctx->varlibfd;
    }else{
        ctx->rootfd=open("/",O_RDONLY|O_DIRECTORY|O_CLOEXEC);
        ctx->varlibfd=open("/var/lib",O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
        ctx->bindirfd=open("/usr/local/bin",O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
        usrfd=open("/usr",O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
        localfd=open("/usr/local",O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
        ctx->dataparentfd=ctx->varlibfd;
    }
    if(ctx->rootfd<0||ctx->varlibfd<0||ctx->bindirfd<0||usrfd<0||localfd<0){if(usrfd>=0)close(usrfd);if(localfd>=0)close(localfd);return -1;}
    if(fstat(usrfd,&st)!=0||!mode_safe_dir(&st)||!stat_expected(ctx,&st)){close(usrfd);close(localfd);return -1;}
    if(fstat(localfd,&st)!=0||!mode_safe_dir(&st)||!stat_expected(ctx,&st)){close(usrfd);close(localfd);return -1;}
    close(usrfd);close(localfd);
    if(fstat(ctx->varlibfd,&st)!=0||!mode_safe_dir(&st)||!stat_expected(ctx,&st))return -1;
    if(fstat(ctx->bindirfd,&st)!=0||!mode_safe_dir(&st)||!stat_expected(ctx,&st))return -1;
    ctx->datafd=openat(ctx->varlibfd,"ios-unsandboxed",O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
    if(ctx->datafd>=0){
        if(fstat(ctx->datafd,&st)!=0||!mode_safe_dir(&st)||!stat_expected(ctx,&st)||(st.st_mode&07777)!=0700)return -1;
        ctx->backupsfd=openat(ctx->datafd,"backups",O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
        ctx->stagingfd=openat(ctx->datafd,"staging",O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
        if(ctx->backupsfd<0||ctx->stagingfd<0)return -1;
        if(fstat(ctx->backupsfd,&st)!=0||!mode_safe_dir(&st)||!stat_expected(ctx,&st)||(st.st_mode&07777)!=0700)return -1;
        if(fstat(ctx->stagingfd,&st)!=0||!mode_safe_dir(&st)||!stat_expected(ctx,&st)||(st.st_mode&07777)!=0700)return -1;
    }else if(errno!=ENOENT)return -1;
    return 0;
}
static void close_context(struct context *ctx)
{
    if(ctx->lockfd>=0)close(ctx->lockfd);
    if(ctx->stagingfd>=0)close(ctx->stagingfd);
    if(ctx->backupsfd>=0)close(ctx->backupsfd);
    if(ctx->datafd>=0)close(ctx->datafd);
    if(ctx->bindirfd>=0)close(ctx->bindirfd);
    if(ctx->varlibfd>=0)close(ctx->varlibfd);
    if(ctx->rootfd>=0)close(ctx->rootfd);
}
static int acquire_lock(struct context *ctx)
{
    struct stat st;struct flock lock;
    ctx->lockfd=openat(ctx->varlibfd,".ios-unsandboxed-installer.lock",O_RDWR|O_CREAT|O_NOFOLLOW|O_CLOEXEC,0600);
    if(ctx->lockfd<0)return bad("could not open the transaction lock file");
    if(fstat(ctx->lockfd,&st)!=0||!S_ISREG(st.st_mode)||st.st_nlink!=1||!expected_mode(ctx,&st,0600))return bad("transaction lock file ownership, type, or mode is unsafe");
    memset(&lock,0,sizeof(lock));lock.l_type=F_WRLCK;lock.l_whence=SEEK_SET;
    if(fcntl(ctx->lockfd,F_SETLK,&lock)!=0){if(errno==EACCES||errno==EAGAIN)fail("another installer transaction holds the lock");else fail("could not acquire the transaction lock");return -1;}
    ctx->lock_held=1;
    return 0;
}
static int check_production_platform(const struct context *ctx)
{
    if(ctx->fixture)return 0;
#if defined(__APPLE__)
    char machine[64], product[64]; size_t n=sizeof(machine), p=sizeof(product);
    if(sysctlbyname("hw.machine",machine,&n,NULL,0)!=0)return bad("cannot identify hardware; production mutation refused");
    machine[sizeof(machine)-1]='\0';
    if(strcmp(machine,"iPad4,4")!=0)return bad("production mutation is limited to the iPad mini 2 Wi-Fi (A1489) reference target");
    if(sysctlbyname("kern.osproductversion",product,&p,NULL,0)!=0)return bad("cannot identify iOS product version; production mutation refused");
    product[sizeof(product)-1]='\0';
    if(strcmp(product,"12.5.7")!=0)return bad("production mutation is limited to iOS 12.5.7");
    return 0;
#else
    (void)ctx;
    return bad("production mutation requires a supported Darwin iOS target; use --test-root only for isolated fixtures");
#endif
}

static int readlink_hash_at(int dirfd,const char *name,const char *expected,char hash[HASH_HEX],uid_t uid,gid_t gid)
{
    struct stat st;char target[PATH_MAX];ssize_t n;
    if(fstatat(dirfd,name,&st,AT_SYMLINK_NOFOLLOW)!=0||!S_ISLNK(st.st_mode)||st.st_nlink!=1||st.st_uid!=uid||st.st_gid!=gid){errno=EPERM;return -1;}
    n=readlinkat(dirfd,name,target,sizeof(target)-1U);if(n<0)return -1;target[n]='\0';
    if(strcmp(target,expected)!=0){errno=EPERM;return -1;}
    hash_hex((const uint8_t*)target,(size_t)n,hash);return 0;
}
static int parent_for_index(struct context *ctx,size_t index)
{
    if(index<=2U)return ctx->bindirfd;
    return ctx->datafd;
}
static int hash_named_file(int dirfd,const char *name,char hash[HASH_HEX],struct stat *out)
{
    int fd;struct stat before,after;
    fd=openat(dirfd,name,O_RDONLY|O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC);if(fd<0)return -1;
    if(fstat(fd,&before)!=0||!S_ISREG(before.st_mode)||before.st_nlink!=1){close(fd);errno=EPERM;return -1;}
    if(hash_fd(fd,hash)!=0||fstat(fd,&after)!=0){int e=errno;close(fd);errno=e;return -1;}
    close(fd);
    if(before.st_dev!=after.st_dev||before.st_ino!=after.st_ino||before.st_size!=after.st_size||before.st_mtime!=after.st_mtime||before.st_ctime!=after.st_ctime){errno=EPERM;return -1;}
    if(out)*out=after;
    return 0;
}
static int verify_entry_at(struct context *ctx,int dirfd,size_t index,const struct manifest_entry *entry)
{
    struct stat st;char hash[HASH_HEX];
    if(FILES[index].type==FILE_SYMLINK){
        if(readlink_hash_at(dirfd,FILES[index].leaf,FILES[index].link_target,hash,entry->uid,entry->gid)!=0)return -1;
        if(strcmp(hash,entry->hash)!=0||entry->mode!=0777)return -1;
        return 0;
    }
    if(hash_named_file(dirfd,FILES[index].leaf,hash,&st)!=0)return -1;
    if(strcmp(hash,entry->hash)!=0||st.st_uid!=entry->uid||st.st_gid!=entry->gid||
       (st.st_mode&07777)!=entry->mode||entry->mode!=FILES[index].mode)return -1;
    (void)ctx;return 0;
}

static int split_fields(char *line,char **fields,size_t expected)
{
    size_t n=0;char *save=NULL,*p=strtok_r(line,"|",&save);
    while(p&&n<expected){fields[n++]=p;p=strtok_r(NULL,"|",&save);}
    return n==expected&&p==NULL?0:-1;
}
static int parse_uid_gid(const char *uid_s,const char *gid_s,uid_t *uid,gid_t *gid)
{
    char *end;unsigned long u,g;
    errno=0;u=strtoul(uid_s,&end,10);if(errno||*end||u>(unsigned long)(uid_t)-1)return -1;
    errno=0;g=strtoul(gid_s,&end,10);if(errno||*end||g>(unsigned long)(gid_t)-1)return -1;
    *uid=(uid_t)u;*gid=(gid_t)g;return 0;
}
static int parse_octal_mode(const char *s,unsigned *mode)
{
    unsigned v=0;size_t i;if(strlen(s)!=4U||s[0]!='0')return -1;
    for(i=1;i<4U;++i){if(s[i]<'0'||s[i]>'7')return -1;v=(v<<3)|(unsigned)(s[i]-'0');}
    *mode=v;return 0;
}
static int parse_file_record(char *line,size_t index,struct manifest_entry *entry)
{
    char *fields[6];unsigned mode;uid_t uid;gid_t gid;enum file_type type;
    if(strncmp(line,"file=",5)!=0)return -1;
    if(split_fields(line+5,fields,6)!=0)return -1;
    if(strcmp(fields[0],FILES[index].destination)!=0)return -1;
    if(strcmp(fields[1],"regular")==0)type=FILE_REGULAR;else if(strcmp(fields[1],"symlink")==0)type=FILE_SYMLINK;else return -1;
    if(type!=FILES[index].type||parse_octal_mode(fields[2],&mode)!=0||mode!=FILES[index].mode||
       parse_uid_gid(fields[3],fields[4],&uid,&gid)!=0||!is_hex64(fields[5]))return -1;
    entry->type=type;entry->mode=mode;entry->uid=uid;entry->gid=gid;strcpy(entry->hash,fields[5]);return 0;
}
static int parse_manifest_text(char *text,struct manifest *out,int backup,const char *expected_generation)
{
    char *save=NULL,*line;size_t index=0;int phase=0;
    memset(out,0,sizeof(*out));
    line=strtok_r(text,"\n",&save);if(!line||strcmp(line,backup?"ios-unsandboxed-backup":"ios-unsandboxed-install")!=0)return -1;
    line=strtok_r(NULL,"\n",&save);if(!line||strcmp(line,"schema_version=1")!=0)return -1;
    if(backup){
        line=strtok_r(NULL,"\n",&save);if(!line||strncmp(line,"generation=",11)!=0||!safe_generation(line+11)||strcmp(line+11,expected_generation)!=0)return -1;
        line=strtok_r(NULL,"\n",&save);if(!line||strncmp(line,"project_version=",16)!=0||!safe_project_version(line+16))return -1;
        strcpy(out->project_version,line+16);
        line=strtok_r(NULL,"\n",&save);if(!line||strncmp(line,"package_generation=",19)!=0||!is_hex64(line+19))return -1;
        strcpy(out->package_generation,line+19);
        line=strtok_r(NULL,"\n",&save);if(!line||strncmp(line,"previous_backup_generation=",27)!=0)return -1;
        if(strcmp(line+27,"none")!=0&&!safe_generation(line+27))return -1;
        strcpy(out->backup_generation,line+27);
        line=strtok_r(NULL,"\n",&save);if(!line||strncmp(line,"signing_status=",15)!=0)return -1;
        if(!known_signing_status(line+15))return -1;
        strcpy(out->signing_status,line+15);
        phase=1;
    }else{
        line=strtok_r(NULL,"\n",&save);if(!line||strncmp(line,"project_version=",16)!=0||!safe_project_version(line+16))return -1;
        strcpy(out->project_version,line+16);
        line=strtok_r(NULL,"\n",&save);if(!line||strncmp(line,"package_generation=",19)!=0||!is_hex64(line+19))return -1;
        strcpy(out->package_generation,line+19);
        line=strtok_r(NULL,"\n",&save);if(!line||strncmp(line,"backup_generation=",18)!=0)return -1;
        if(strcmp(line+18,"none")!=0&&!safe_generation(line+18))return -1;
        strcpy(out->backup_generation,line+18);
        line=strtok_r(NULL,"\n",&save);if(!line||strncmp(line,"signing_status=",15)!=0)return -1;
        if(!known_signing_status(line+15))return -1;
        strcpy(out->signing_status,line+15);
        line=strtok_r(NULL,"\n",&save);if(!line||strcmp(line,"transaction_status=committed")!=0)return -1;
        phase=1;
    }
    (void)phase;
    for(index=0;index<FILE_COUNT;++index){line=strtok_r(NULL,"\n",&save);if(!line||parse_file_record(line,index,&out->files[index])!=0)return -1;}
    if(strtok_r(NULL,"\n",&save)!=NULL)return -1;
    return 0;
}
static int load_manifest_fd(struct context *ctx,struct manifest *m)
{
    char text[MAX_META_BYTES];size_t len;int fd;struct stat st;
    if(ctx->datafd<0)return 1;
    fd=openat(ctx->datafd,"install-manifest",O_RDONLY|O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC);
    if(fd<0)return errno==ENOENT?1:-1;
    if(fstat(fd,&st)!=0||!S_ISREG(st.st_mode)||st.st_nlink!=1||!expected_mode(ctx,&st,0600)||st.st_size<0||st.st_size>=MAX_META_BYTES){close(fd);return -1;}
    if(read_all_fd(fd,text,sizeof(text)-1,&len)!=0){close(fd);return -1;}close(fd);
    if(len==0||text[len-1]!='\n'||!valid_metadata_bytes(text,len))return -1;
    text[len-1]='\0';
    if(parse_manifest_text(text,m,0,NULL)!=0)return -1;
    for(size_t i=0;i<FILE_COUNT;++i){int parent=parent_for_index(ctx,i);if(verify_entry_at(ctx,parent,i,&m->files[i])!=0)return -1;}
    return 0;
}
static int load_backup(struct context *ctx,const char *generation,struct manifest *m,int *backup_dirfd)
{
    int bfd,filesfd,fd;char text[MAX_META_BYTES];size_t len;struct stat st;
    if(!safe_generation(generation)||ctx->backupsfd<0)return -1;
    bfd=openat(ctx->backupsfd,generation,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);if(bfd<0)return -1;
    if(fstat(bfd,&st)!=0||!mode_safe_dir(&st)||!expected_mode(ctx,&st,0700)){close(bfd);return -1;}
    filesfd=openat(bfd,"files",O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);if(filesfd<0){close(bfd);return -1;}
    if(fstat(filesfd,&st)!=0||!mode_safe_dir(&st)||!expected_mode(ctx,&st,0700)){close(filesfd);close(bfd);return -1;}
    fd=openat(bfd,"backup-manifest",O_RDONLY|O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC);
    if(fd<0){close(filesfd);close(bfd);return -1;}
    if(fstat(fd,&st)!=0||!S_ISREG(st.st_mode)||st.st_nlink!=1||!expected_mode(ctx,&st,0600)||st.st_size<0||st.st_size>=MAX_META_BYTES||read_all_fd(fd,text,sizeof(text)-1,&len)!=0){close(fd);close(filesfd);close(bfd);return -1;}
    close(fd);if(len==0||text[len-1]!='\n'||!valid_metadata_bytes(text,len)){close(filesfd);close(bfd);return -1;}text[len-1]='\0';
    if(parse_manifest_text(text,m,1,generation)!=0){close(filesfd);close(bfd);return -1;}
    for(size_t i=0;i<FILE_COUNT;++i){char leaf[8],hash[HASH_HEX];struct stat fs;
        snprintf(leaf,sizeof(leaf),"f%zu",i);
        if(FILES[i].type==FILE_SYMLINK){
            if(readlink_hash_at(filesfd,leaf,FILES[i].link_target,hash,m->files[i].uid,m->files[i].gid)!=0||strcmp(hash,m->files[i].hash)!=0){close(filesfd);close(bfd);return -1;}
        }else if(hash_named_file(filesfd,leaf,hash,&fs)!=0||strcmp(hash,m->files[i].hash)!=0||!expected_mode(ctx,&fs,m->files[i].mode)){close(filesfd);close(bfd);return -1;}
    }
    close(filesfd);*backup_dirfd=bfd;return 0;
}

static int package_file_hash(int packagefd,const char *path,char hash[HASH_HEX],unsigned mode,struct context *ctx,int check_macho)
{
    char copy[PATH_MAX],*save=NULL,*part;int dir=dup(packagefd),next=-1,fd=-1;struct stat st;
    if(strlen(path)>=sizeof(copy)||dir<0)return -1;
    strcpy(copy,path);part=strtok_r(copy,"/",&save);
    while(part){char *following=strtok_r(NULL,"/",&save);if(!following){fd=openat(dir,part,O_RDONLY|O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC);break;}next=openat(dir,part,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);close(dir);if(next<0)return -1;dir=next;part=following;}
    if(fd<0){if(dir>=0)close(dir);return -1;}
    if(fstat(fd,&st)!=0||!S_ISREG(st.st_mode)||st.st_nlink!=1||!stat_expected(ctx,&st)||(st.st_mode&07777)!=mode){close(fd);if(dir>=0)close(dir);errno=EPERM;return -1;}
    if(hash_fd(fd,hash)!=0){close(fd);if(dir>=0)close(dir);return -1;}
    if(check_macho){
        uint8_t header[32];uint32_t ncmds,sizeofcmds;off_t offset=32;int has_ios=0;
        if(pread(fd,header,sizeof(header),0)!=(ssize_t)sizeof(header)||header[0]!=0xcf||header[1]!=0xfa||header[2]!=0xed||header[3]!=0xfe||
           header[4]!=0x0c||header[5]!=0x00||header[6]!=0x00||header[7]!=0x01||header[12]!=2){close(fd);if(dir>=0)close(dir);errno=ENOEXEC;return -1;}
        ncmds=load_le32(header+16);sizeofcmds=load_le32(header+20);
        if(ncmds>4096U||sizeofcmds>1024U*1024U){close(fd);if(dir>=0)close(dir);errno=ENOEXEC;return -1;}
        for(uint32_t i=0;i<ncmds;++i){uint8_t lc[24];uint32_t cmd,cmdsize;
            if(pread(fd,lc,8,offset)!=8){close(fd);if(dir>=0)close(dir);errno=ENOEXEC;return -1;}
            cmd=load_le32(lc);cmdsize=load_le32(lc+4);
            if(cmdsize<8U||cmdsize>sizeofcmds){close(fd);if(dir>=0)close(dir);errno=ENOEXEC;return -1;}
            if(cmd==0x32U&&cmdsize>=24U){uint32_t platform,minos;if(pread(fd,lc,24,offset)!=24){close(fd);if(dir>=0)close(dir);return -1;}platform=load_le32(lc+8);minos=load_le32(lc+12);if(platform==2U&&minos==0x000c0000U)has_ios=1;}
            if(cmd==0x25U&&cmdsize>=16U){uint32_t version;if(pread(fd,lc,16,offset)!=16){close(fd);if(dir>=0)close(dir);return -1;}version=load_le32(lc+8);if(version==0x000c0000U)has_ios=1;}
            offset+=(off_t)cmdsize;sizeofcmds-=cmdsize;
        }
        if(!has_ios||sizeofcmds!=0U){close(fd);if(dir>=0)close(dir);errno=ENOEXEC;return -1;}
    }
    close(fd);if(dir>=0)close(dir);return 0;
}

static int verify_package_directory(struct context *ctx,const char *path,struct package *pkg)
{
    struct stat st;char text[MAX_META_BYTES],sum_text[MAX_META_BYTES],manifest_hash[HASH_HEX];size_t len,sum_len;int fd;
    memset(pkg,0,sizeof(*pkg));pkg->dirfd=-1;
    if(path==NULL||path[0]=='\0')return -1;
    pkg->dirfd=open(path,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);if(pkg->dirfd<0)return -1;
    if(fstat(pkg->dirfd,&st)!=0||!mode_safe_package(&st)||!stat_expected(ctx,&st)){close(pkg->dirfd);pkg->dirfd=-1;return -1;}
    fd=openat(pkg->dirfd,"package-manifest",O_RDONLY|O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC);
    if(fd<0){close(pkg->dirfd);pkg->dirfd=-1;return -1;}
    if(fstat(fd,&st)!=0||!S_ISREG(st.st_mode)||st.st_nlink!=1||!stat_expected(ctx,&st)||(st.st_mode&07777)!=0644||read_all_fd(fd,text,sizeof(text)-1,&len)!=0){close(fd);close(pkg->dirfd);pkg->dirfd=-1;return -1;}
    close(fd);if(len==0||text[len-1]!='\n'||!valid_metadata_bytes(text,len)){close(pkg->dirfd);pkg->dirfd=-1;return -1;}hash_hex((uint8_t*)text,len,manifest_hash);strcpy(pkg->manifest_hash,manifest_hash);text[len-1]='\0';
    {
        char *save=NULL,*line=strtok_r(text,"\n",&save);size_t i;
        if(!line||strcmp(line,"ios-unsandboxed-package")!=0)goto invalid;
        line=strtok_r(NULL,"\n",&save);if(!line||strcmp(line,"schema_version=1")!=0)goto invalid;
        line=strtok_r(NULL,"\n",&save);if(!line||strncmp(line,"project_version=",16)!=0||!safe_project_version(line+16))goto invalid;strcpy(pkg->version,line+16);
        line=strtok_r(NULL,"\n",&save);if(!line||strcmp(line,"platform=ios")!=0)goto invalid;
        line=strtok_r(NULL,"\n",&save);if(!line||strcmp(line,"architecture=arm64")!=0)goto invalid;
        line=strtok_r(NULL,"\n",&save);if(!line||strcmp(line,"minimum_ios=12.0")!=0)goto invalid;
        line=strtok_r(NULL,"\n",&save);if(!line||strncmp(line,"signing_status=",15)!=0)goto invalid;
        for(i=0;i<sizeof(SIGNING_VALUES)/sizeof(SIGNING_VALUES[0]);++i)if(strcmp(line+15,SIGNING_VALUES[i])==0)break;
        if(i==sizeof(SIGNING_VALUES)/sizeof(SIGNING_VALUES[0]))goto invalid;
        strcpy(pkg->signing,line+15);
        line=strtok_r(NULL,"\n",&save);if(!line||strncmp(line,"signature_verification=",23)!=0)goto invalid;
        if(strcmp(line+23,"passed")&&strcmp(line+23,"failed")&&strcmp(line+23,"not_applicable")&&strcmp(line+23,"unknown")&&strcmp(line+23,"mixed"))goto invalid;
        strcpy(pkg->signature_verification,line+23);
        for(i=0;i<3U;++i){char *fields[3];size_t j;line=strtok_r(NULL,"\n",&save);if(!line||strncmp(line,"artifact_signing=",17)!=0||split_fields(line+17,fields,3)!=0)goto invalid;
            if(strcmp(fields[0],MACH_O_PATHS[i])!=0)goto invalid;
            for(j=0;j<sizeof(SIGNING_VALUES)/sizeof(SIGNING_VALUES[0]);++j)if(strcmp(fields[1],SIGNING_VALUES[j])==0)break;
            if(j==sizeof(SIGNING_VALUES)/sizeof(SIGNING_VALUES[0]))goto invalid;
            if(strcmp(fields[2],"passed")&&strcmp(fields[2],"failed")&&strcmp(fields[2],"not_applicable")&&strcmp(fields[2],"unknown"))goto invalid;
        }
        for(i=0;i<PACKAGE_FILE_COUNT;++i){char *fields[4];unsigned mode;line=strtok_r(NULL,"\n",&save);if(!line||strncmp(line,"file=",5)!=0||split_fields(line+5,fields,4)!=0)goto invalid;
            if(strcmp(fields[0],PACKAGE_PATHS[i])!=0||strcmp(fields[1],"regular")!=0||parse_octal_mode(fields[2],&mode)!=0||mode!=PACKAGE_MODES[i]||!is_hex64(fields[3]))goto invalid;
            strcpy(pkg->hashes[i],fields[3]);}
        if(strtok_r(NULL,"\n",&save)!=NULL)goto invalid;
    }
    fd=openat(pkg->dirfd,"SHA256SUMS",O_RDONLY|O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC);if(fd<0)goto invalid;
    if(fstat(fd,&st)!=0||!S_ISREG(st.st_mode)||st.st_nlink!=1||!stat_expected(ctx,&st)||(st.st_mode&07777)!=0644||read_all_fd(fd,sum_text,sizeof(sum_text)-1,&sum_len)!=0){close(fd);goto invalid;}close(fd);
    if(sum_len==0||sum_text[sum_len-1]!='\n'||!valid_metadata_bytes(sum_text,sum_len))goto invalid;
    sum_text[sum_len-1]='\0';
    {
        char expected[MAX_META_BYTES],*cursor=expected;size_t i;int n;
        n=snprintf(cursor,sizeof(expected),"%s  package-manifest\n",pkg->manifest_hash);if(n<0||(size_t)n>=sizeof(expected))goto invalid;cursor+=n;
        for(i=0;i<PACKAGE_FILE_COUNT;++i){n=snprintf(cursor,sizeof(expected)-(size_t)(cursor-expected),"%s  %s\n",pkg->hashes[i],PACKAGE_PATHS[i]);if(n<0||(size_t)n>=sizeof(expected)-(size_t)(cursor-expected))goto invalid;cursor+=n;}
        if(strlen(expected)==0||strlen(expected)-1U!=strlen(sum_text)||memcmp(expected,sum_text,strlen(sum_text))!=0)goto invalid;
    }
    for(size_t i=0;i<PACKAGE_FILE_COUNT;++i){char actual[HASH_HEX];int macho=(i==0||i==1||i==3);
        if(package_file_hash(pkg->dirfd,PACKAGE_PATHS[i],actual,PACKAGE_MODES[i],ctx,macho)!=0||strcmp(actual,pkg->hashes[i])!=0)goto invalid;
    }
    /* The plist is checked as XML on the build host. Its target and safety
     * fields are checked again here as fixed text, before it is staged inactive. */
    {
        char plist[16384];size_t n;int plistfd=openat(pkg->dirfd,"payload",O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC),share;
        if(plistfd<0)goto invalid;
        share=openat(plistfd,"share",O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);close(plistfd);if(share<0)goto invalid;
        int pfd=openat(share,"com.ios-unsandboxed.daemon.plist",O_RDONLY|O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC);close(share);if(pfd<0)goto invalid;
        if(read_all_fd(pfd,plist,sizeof(plist)-1,&n)!=0){close(pfd);goto invalid;}close(pfd);
        if(strstr(plist,"/usr/local/bin/ios-unsandboxedd")==NULL||strstr(plist,"<key>KeepAlive</key>\n\t<false/>")==NULL||strstr(plist,"<key>RunAtLoad</key>\n\t<true/>")==NULL||strstr(plist,"<string>wheel</string>")==NULL)goto invalid;
    }
    return 0;
invalid:
    close(pkg->dirfd);pkg->dirfd=-1;return -1;
}

static int version_cmp(const char *a,const char *b)
{
    unsigned av[3],bv[3];sscanf(a,"%u.%u.%u",&av[0],&av[1],&av[2]);sscanf(b,"%u.%u.%u",&bv[0],&bv[1],&bv[2]);
    for(size_t i=0;i<3U;++i){if(av[i]<bv[i])return -1;if(av[i]>bv[i])return 1;}return 0;
}

static int ensure_project_data(struct context *ctx)
{
    struct stat st;
    if(ctx->datafd>=0)return 0;
    if(mkdirat(ctx->varlibfd,"ios-unsandboxed",0700)!=0)return -1;
    ctx->data_created=1;
    ctx->datafd=openat(ctx->varlibfd,"ios-unsandboxed",O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);if(ctx->datafd<0)return -1;
    if(fchown(ctx->datafd,ctx->uid,ctx->gid)!=0||fchmod(ctx->datafd,0700)!=0||fstat(ctx->datafd,&st)!=0||!expected_mode(ctx,&st,0700))return -1;
    if(mkdirat(ctx->datafd,"backups",0700)!=0||mkdirat(ctx->datafd,"staging",0700)!=0)return -1;
    ctx->backupsfd=openat(ctx->datafd,"backups",O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);ctx->stagingfd=openat(ctx->datafd,"staging",O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
    if(ctx->backupsfd<0||ctx->stagingfd<0)return -1;
    if(fchown(ctx->backupsfd,ctx->uid,ctx->gid)!=0||fchmod(ctx->backupsfd,0700)!=0||fchown(ctx->stagingfd,ctx->uid,ctx->gid)!=0||fchmod(ctx->stagingfd,0700)!=0)return -1;
    if(fsync_dir(ctx->varlibfd)!=0||fsync_dir(ctx->datafd)!=0)return -1;
    return 0;
}
static int create_generation(char output[80])
{
    struct timespec ts;if(clock_gettime(CLOCK_REALTIME,&ts)!=0)return -1;
    if(snprintf(output,80,"g%lld-%09ld-%ld",(long long)ts.tv_sec,ts.tv_nsec,(long)getpid())>=80)return -1;
    return 0;
}
static int mkdir_owned(int parent,const char *name,struct context *ctx,int *fd_out)
{
    int fd;struct stat st;if(mkdirat(parent,name,0700)!=0)return -1;
    fd=openat(parent,name,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);if(fd<0)return -1;
    if(fchown(fd,ctx->uid,ctx->gid)!=0||fchmod(fd,0700)!=0||fstat(fd,&st)!=0||!expected_mode(ctx,&st,0700)){close(fd);return -1;}
    *fd_out=fd;return 0;
}
static int write_atomic(int dirfd,const char *leaf,const void *bytes,size_t length,struct context *ctx,mode_t mode)
{
    char tmp[96];int fd;struct stat st;static unsigned counter;
    snprintf(tmp,sizeof(tmp),".tmp-%ld-%u",(long)getpid(),++counter);
    fd=openat(dirfd,tmp,O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0600);if(fd<0)return -1;
    if(write_all(fd,bytes,length)!=0||fchmod(fd,mode)!=0||fchown(fd,ctx->uid,ctx->gid)!=0||fsync(fd)!=0){int e=errno;close(fd);unlinkat(dirfd,tmp,0);errno=e;return -1;}
    if(fstat(fd,&st)!=0||!expected_mode(ctx,&st,(unsigned)mode)){close(fd);unlinkat(dirfd,tmp,0);errno=EPERM;return -1;}
    if(close(fd)!=0){unlinkat(dirfd,tmp,0);return -1;}
    if(renameat(dirfd,tmp,dirfd,leaf)!=0){int e=errno;unlinkat(dirfd,tmp,0);errno=e;return -1;}
    return fsync_dir(dirfd);
}
static int make_manifest_text(const struct manifest *m,char *out,size_t cap,int backup,const char *generation,size_t *length)
{
    size_t used=0;int n;
#define APPEND(...) do{n=snprintf(out+used,cap-used,__VA_ARGS__);if(n<0||(size_t)n>=cap-used)return -1;used+=(size_t)n;}while(0)
    if(backup){APPEND("ios-unsandboxed-backup\nschema_version=1\ngeneration=%s\nproject_version=%s\npackage_generation=%s\nprevious_backup_generation=%s\nsigning_status=%s\n",generation,m->project_version,m->package_generation,m->backup_generation,m->signing_status);}
    else{APPEND("ios-unsandboxed-install\nschema_version=1\nproject_version=%s\npackage_generation=%s\nbackup_generation=%s\nsigning_status=%s\ntransaction_status=committed\n",m->project_version,m->package_generation,m->backup_generation,m->signing_status);}
    for(size_t i=0;i<FILE_COUNT;++i)APPEND("file=%s|%s|%04o|%u|%u|%s\n",FILES[i].destination,m->files[i].type==FILE_SYMLINK?"symlink":"regular",m->files[i].mode,(unsigned)m->files[i].uid,(unsigned)m->files[i].gid,m->files[i].hash);
    *length=used;return 0;
#undef APPEND
}
static int create_backup(struct context *ctx,const struct manifest *current,char generation[80])
{
    int bfd=-1,filesfd=-1;struct manifest saved=*current;char text[MAX_META_BYTES];size_t len;
    if(create_generation(generation)!=0||mkdir_owned(ctx->stagingfd,generation,ctx,&bfd)!=0)return -1;
    if(mkdir_owned(bfd,"files",ctx,&filesfd)!=0){close(bfd);return -1;}
    for(size_t i=0;i<FILE_COUNT;++i){int srcparent=parent_for_index(ctx,i);char leaf[8];snprintf(leaf,sizeof(leaf),"f%zu",i);
        if(FILES[i].type==FILE_SYMLINK){if(symlinkat(FILES[i].link_target,filesfd,leaf)!=0||fchownat(filesfd,leaf,ctx->uid,ctx->gid,AT_SYMLINK_NOFOLLOW)!=0){close(filesfd);close(bfd);return -1;}}
        else{
            int src=openat(srcparent,FILES[i].leaf,O_RDONLY|O_NOFOLLOW|O_CLOEXEC),dst=-1;struct stat st;char hash[HASH_HEX];uint8_t buf[16384];ssize_t n;
            if(src<0){close(filesfd);close(bfd);return -1;}if(fstat(src,&st)!=0||!S_ISREG(st.st_mode)||st.st_nlink!=1||!expected_mode(ctx,&st,current->files[i].mode)){close(src);close(filesfd);close(bfd);return -1;}
            dst=openat(filesfd,leaf,O_RDWR|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0600);if(dst<0){close(src);close(filesfd);close(bfd);return -1;}
            while((n=read(src,buf,sizeof(buf)))>0)if(write_all(dst,buf,(size_t)n)!=0){close(src);close(dst);close(filesfd);close(bfd);return -1;}
            if(n<0||fchmod(dst,current->files[i].mode)!=0||fchown(dst,ctx->uid,ctx->gid)!=0||fsync(dst)!=0||hash_fd(dst,hash)!=0||strcmp(hash,current->files[i].hash)!=0){close(src);close(dst);close(filesfd);close(bfd);return -1;}
            close(src);close(dst);
        }
    }
    if(make_manifest_text(&saved,text,sizeof(text),1,generation,&len)!=0||write_atomic(bfd,"backup-manifest",text,len,ctx,0600)!=0||fsync_dir(filesfd)!=0||fsync_dir(bfd)!=0){close(filesfd);close(bfd);return -1;}
    close(filesfd);close(bfd);
    if(renameat(ctx->stagingfd,generation,ctx->backupsfd,generation)!=0)return -1;
    if(fsync_dir(ctx->stagingfd)!=0||fsync_dir(ctx->backupsfd)!=0)return -1;
    return 0;
}
static int write_transaction(struct context *ctx,const struct transaction *t)
{
    char text[1024];int n=snprintf(text,sizeof(text),"ios-unsandboxed-transaction\nschema_version=1\naction=%s\nrecovery_generation=%s\ntarget_generation=%s\nstaging_generation=%s\npackage_generation=%s\nphase=%s\n",t->action,t->recovery_generation,t->target_generation,t->staging_generation,t->package_generation,t->phase);
    if(n<0||(size_t)n>=sizeof(text))return -1;
    return write_atomic(ctx->datafd,"transaction",text,(size_t)n,ctx,0600);
}
static int load_transaction(struct context *ctx,struct transaction *t)
{
    char text[1024],*save=NULL,*line;size_t len;
    if(ctx->datafd<0)return 1;
    if(read_named(ctx->datafd,"transaction",text,sizeof(text)-1,&len,0600,ctx->uid,ctx->gid)!=0)return errno==ENOENT?1:-1;
    if(len==0||text[len-1]!='\n'||!valid_metadata_bytes(text,len))return -1;
    text[len-1]='\0';
    memset(t,0,sizeof(*t));line=strtok_r(text,"\n",&save);if(!line||strcmp(line,"ios-unsandboxed-transaction")!=0)return -1;
    line=strtok_r(NULL,"\n",&save);if(!line||strcmp(line,"schema_version=1")!=0)return -1;
    line=strtok_r(NULL,"\n",&save);if(!line||strncmp(line,"action=",7)!=0)return -1;
    if(strcmp(line+7,"install")&&strcmp(line+7,"upgrade")&&strcmp(line+7,"rollback")&&strcmp(line+7,"uninstall"))return -1;
    strcpy(t->action,line+7);
    line=strtok_r(NULL,"\n",&save);if(!line||strncmp(line,"recovery_generation=",20)!=0)return -1;
    if(strlen(line+20)>=sizeof(t->recovery_generation)||(strcmp(line+20,"none")&&!safe_generation(line+20)))return -1;
    strcpy(t->recovery_generation,line+20);
    line=strtok_r(NULL,"\n",&save);if(!line||strncmp(line,"target_generation=",18)!=0)return -1;
    if(strlen(line+18)>=sizeof(t->target_generation)||(strcmp(line+18,"none")&&!safe_generation(line+18)))return -1;
    strcpy(t->target_generation,line+18);
    line=strtok_r(NULL,"\n",&save);if(!line||strncmp(line,"staging_generation=",19)!=0)return -1;
    if(strlen(line+19)>=sizeof(t->staging_generation)||(strcmp(line+19,"none")&&!safe_generation(line+19)))return -1;
    strcpy(t->staging_generation,line+19);
    line=strtok_r(NULL,"\n",&save);if(!line||strncmp(line,"package_generation=",19)!=0||!is_hex64(line+19))return -1;strcpy(t->package_generation,line+19);
    line=strtok_r(NULL,"\n",&save);if(!line||strncmp(line,"phase=",6)!=0)return -1;
    if(strcmp(line+6,"prepared")&&strcmp(line+6,"committing")&&strcmp(line+6,"manifest_written")&&strcmp(line+6,"state_written"))return -1;
    strcpy(t->phase,line+6);
    if(strtok_r(NULL,"\n",&save)!=NULL)return -1;
    return 0;
}

static int package_source_fd(int packagefd,const char *path)
{
    char copy[PATH_MAX],*save=NULL,*part;int dir=dup(packagefd),next=-1,fd=-1;
    if(dir<0||strlen(path)>=sizeof(copy)){if(dir>=0)close(dir);return -1;}strcpy(copy,path);part=strtok_r(copy,"/",&save);
    while(part){char *following=strtok_r(NULL,"/",&save);if(!following){fd=openat(dir,part,O_RDONLY|O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC);break;}
        next=openat(dir,part,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);close(dir);if(next<0)return -1;dir=next;part=following;}
    if(dir>=0)close(dir);
    return fd;
}
static int copy_fd_to_new_file(int source,int target_dir,const char *target_leaf,struct context *ctx,unsigned mode,const char *expected_hash)
{
    uint8_t buf[16384];ssize_t n;int dst;char hash[HASH_HEX];struct stat st;
    dst=openat(target_dir,target_leaf,O_RDWR|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0600);if(dst<0)return -1;
    if(lseek(source,0,SEEK_SET)<0){close(dst);unlinkat(target_dir,target_leaf,0);return -1;}
    while((n=read(source,buf,sizeof(buf)))>0){if(write_all(dst,buf,(size_t)n)!=0){int e=errno;close(dst);unlinkat(target_dir,target_leaf,0);errno=e;return -1;}}
    if(n<0||fchmod(dst,mode)!=0||fchown(dst,ctx->uid,ctx->gid)!=0||fsync(dst)!=0||hash_fd(dst,hash)!=0||strcmp(hash,expected_hash)!=0||fstat(dst,&st)!=0||!expected_mode(ctx,&st,mode)){
        int e=errno?errno:EPERM;close(dst);unlinkat(target_dir,target_leaf,0);errno=e;return -1;}
    if(close(dst)!=0){unlinkat(target_dir,target_leaf,0);return -1;}return 0;
}
static int stage_package(struct context *ctx,const struct package *pkg,const char *generation,struct manifest *m)
{
    int txfd=-1,source=-1;char leaf[8];struct stat st;
    if(mkdir_owned(ctx->stagingfd,generation,ctx,&txfd)!=0)return -1;
    memset(m,0,sizeof(*m));strcpy(m->project_version,pkg->version);strcpy(m->package_generation,pkg->manifest_hash);strcpy(m->signing_status,pkg->signing);strcpy(m->backup_generation,"none");
    for(size_t i=0;i<FILE_COUNT;++i){struct manifest_entry *e=&m->files[i];e->uid=ctx->uid;e->gid=ctx->gid;e->mode=FILES[i].mode;e->type=FILES[i].type;
        snprintf(leaf,sizeof(leaf),"f%zu",i);
        if(i==1U){if(symlinkat(FILES[i].link_target,txfd,leaf)!=0||fchownat(txfd,leaf,ctx->uid,ctx->gid,AT_SYMLINK_NOFOLLOW)!=0){close(txfd);return -1;}hash_hex((const uint8_t*)FILES[i].link_target,strlen(FILES[i].link_target),e->hash);continue;}
        if(i==7U){static const char state[]="ios-unsandboxed-state\nschema_version=1\nservice_installation=installed\nexecution_activation=disabled\n";
            hash_hex((const uint8_t*)state,sizeof(state)-1U,e->hash);if(write_atomic(txfd,leaf,state,sizeof(state)-1U,ctx,0600)!=0){close(txfd);return -1;}continue;}
        int package_index=FILES[i].package_index;
        if(package_index<0||(size_t)package_index>=PACKAGE_FILE_COUNT){close(txfd);return -1;}
        size_t pi=(size_t)package_index;
        source=package_source_fd(pkg->dirfd,PACKAGE_PATHS[pi]);if(source<0){close(txfd);return -1;}
        strcpy(e->hash,pkg->hashes[pi]);if(copy_fd_to_new_file(source,txfd,leaf,ctx,FILES[i].mode,e->hash)!=0){close(source);close(txfd);return -1;}close(source);source=-1;
    }
    if(fstat(txfd,&st)!=0||!expected_mode(ctx,&st,0700)||fsync_dir(txfd)!=0){close(txfd);return -1;}
    close(txfd);return 0;
}
static int stage_backup(struct context *ctx,const char *backup_generation,const char *stage_generation,struct manifest *staged,const char *backup_pointer)
{
    int backupfd=-1,filesfd=-1,stagefd=-1;struct manifest original;char srcleaf[8],dstleaf[8],text[MAX_META_BYTES];size_t len;
    if(load_backup(ctx,backup_generation,&original,&backupfd)!=0)return -1;
    filesfd=openat(backupfd,"files",O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);if(filesfd<0){close(backupfd);return -1;}
    if(mkdir_owned(ctx->stagingfd,stage_generation,ctx,&stagefd)!=0){close(filesfd);close(backupfd);return -1;}
    *staged=original;strcpy(staged->backup_generation,backup_pointer);
    for(size_t i=0;i<FILE_COUNT;++i){snprintf(srcleaf,sizeof(srcleaf),"f%zu",i);snprintf(dstleaf,sizeof(dstleaf),"f%zu",i);
        if(FILES[i].type==FILE_SYMLINK){if(symlinkat(FILES[i].link_target,stagefd,dstleaf)!=0||fchownat(stagefd,dstleaf,ctx->uid,ctx->gid,AT_SYMLINK_NOFOLLOW)!=0){close(stagefd);close(filesfd);close(backupfd);return -1;}}
        else{int src=openat(filesfd,srcleaf,O_RDONLY|O_NOFOLLOW|O_CLOEXEC);if(src<0||copy_fd_to_new_file(src,stagefd,dstleaf,ctx,staged->files[i].mode,staged->files[i].hash)!=0){if(src>=0)close(src);close(stagefd);close(filesfd);close(backupfd);return -1;}close(src);}
    }
    if(make_manifest_text(staged,text,sizeof(text),0,NULL,&len)!=0||write_atomic(stagefd,"manifest",text,len,ctx,0600)!=0||fsync_dir(stagefd)!=0){close(stagefd);close(filesfd);close(backupfd);return -1;}
    close(stagefd);close(filesfd);close(backupfd);return 0;
}
static int stage_manifest_text(int stagefd,struct manifest *m,struct context *ctx)
{
    char text[MAX_META_BYTES];size_t len;int fd;struct stat st;
    fd=openat(stagefd,"manifest",O_RDONLY|O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC);if(fd<0)return -1;
    if(fstat(fd,&st)!=0||!S_ISREG(st.st_mode)||st.st_nlink!=1||!expected_mode(ctx,&st,0600)||st.st_size<0||st.st_size>=MAX_META_BYTES||read_all_fd(fd,text,sizeof(text)-1,&len)!=0){close(fd);return -1;}close(fd);
    if(len==0||text[len-1]!='\n'||!valid_metadata_bytes(text,len))return -1;
    text[len-1]='\0';return parse_manifest_text(text,m,0,NULL);
}
static int create_transaction_backup(struct context *ctx,const struct manifest *current,char generation[80])
{
    if(create_backup(ctx,current,generation)!=0)return -1;
    return 0;
}
static int ensure_absent(struct context *ctx,size_t index)
{
    struct stat st;int parent=parent_for_index(ctx,index);
    if(index>=3U&&ctx->datafd<0)return 0;
    if(fstatat(parent,FILES[index].leaf,&st,AT_SYMLINK_NOFOLLOW)==0){errno=EEXIST;return -1;}
    return errno==ENOENT?0:-1;
}
static int install_one_from_stage(struct context *ctx,int stagefd,size_t index,const struct manifest_entry *entry,const struct manifest_entry *old_entry)
{
    int parent=parent_for_index(ctx,index);struct stat existing;char source_leaf[8],tmp[96];static unsigned counter;struct stat st;
    snprintf(source_leaf,sizeof(source_leaf),"f%zu",index);
    if(fstatat(parent,FILES[index].leaf,&existing,AT_SYMLINK_NOFOLLOW)==0){
        if(old_entry==NULL||verify_entry_at(ctx,parent,index,old_entry)!=0){errno=EEXIST;return -1;}
    }else if(errno!=ENOENT)return -1;
    else if(old_entry!=NULL){errno=ENOENT;return -1;}
    snprintf(tmp,sizeof(tmp),".iu-tmp-%ld-%zu-%u",(long)getpid(),index,++counter);
    if(entry->type==FILE_SYMLINK){
        if(symlinkat(FILES[index].link_target,parent,tmp)!=0)return -1;
        if(fchownat(parent,tmp,ctx->uid,ctx->gid,AT_SYMLINK_NOFOLLOW)!=0){int e=errno;unlinkat(parent,tmp,0);errno=e;return -1;}
    }else{
        int src=openat(stagefd,source_leaf,O_RDONLY|O_NOFOLLOW|O_CLOEXEC),dst=-1;uint8_t buf[16384];ssize_t n;char hash[HASH_HEX];
        if(src<0)return -1;
        if(hash_fd(src,hash)!=0||strcmp(hash,entry->hash)!=0){close(src);errno=EBADMSG;return -1;}
        dst=openat(parent,tmp,O_RDWR|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0600);if(dst<0){close(src);return -1;}
        if(lseek(src,0,SEEK_SET)<0){close(src);close(dst);unlinkat(parent,tmp,0);return -1;}
        while((n=read(src,buf,sizeof(buf)))>0)if(write_all(dst,buf,(size_t)n)!=0){close(src);close(dst);unlinkat(parent,tmp,0);return -1;}
        if(n<0||fchown(dst,ctx->uid,ctx->gid)!=0||fchmod(dst,entry->mode)!=0||fsync(dst)!=0||hash_fd(dst,hash)!=0||strcmp(hash,entry->hash)!=0||fstat(dst,&st)!=0||!expected_mode(ctx,&st,entry->mode)){
            int e=errno?errno:EPERM;close(src);close(dst);unlinkat(parent,tmp,0);errno=e;return -1;}
        close(src);close(dst);
    }
    /* Rename replaces only the exact, just-verified destination in a directory
     * that is root-owned and not group/world writable. A single global atomic
     * commit is impossible because /usr/local and /var may be separate mounts. */
    if(old_entry!=NULL){if(fstatat(parent,FILES[index].leaf,&existing,AT_SYMLINK_NOFOLLOW)!=0||verify_entry_at(ctx,parent,index,old_entry)!=0){unlinkat(parent,tmp,0);errno=EPERM;return -1;}}
    else if(fstatat(parent,FILES[index].leaf,&existing,AT_SYMLINK_NOFOLLOW)==0||errno!=ENOENT){unlinkat(parent,tmp,0);errno=EEXIST;return -1;}
    if(renameat(parent,tmp,parent,FILES[index].leaf)!=0){int e=errno;unlinkat(parent,tmp,0);errno=e;return -1;}
    return fsync_dir(parent);
}
static int write_install_manifest(struct context *ctx,const struct manifest *m)
{
    char text[MAX_META_BYTES];size_t len;
    if(make_manifest_text(m,text,sizeof(text),0,NULL,&len)!=0)return -1;
    return write_atomic(ctx->datafd,"install-manifest",text,len,ctx,0600);
}
static int verify_state_reader(struct context *ctx)
{
    char path[PATH_MAX];struct iu_service_state_result_v1 result;
    if(ctx->fixture){if(snprintf(path,sizeof(path),"%s/var/lib/ios-unsandboxed/install-state",ctx->root)>=(int)sizeof(path))return -1;}
    else strcpy(path,"/var/lib/ios-unsandboxed/install-state");
    if(iu_service_state_load_v1(path,ctx->uid,ctx->gid,ctx->uid,ctx->gid,&result)!=0||result.state_status!=IU_SERVICE_STATE_VALID||result.execution_activation!=IU_EXECUTION_ACTIVATION_DISABLED)return -1;
    return 0;
}
static int stage_copy_out(int stagefd,const char *source_leaf,int parent,const char *target_leaf,struct context *ctx,const struct manifest_entry *entry,const struct manifest_entry *old_entry)
{
    struct stat existing;char tmp[96];static unsigned counter;snprintf(tmp,sizeof(tmp),".iu-meta-%ld-%u",(long)getpid(),++counter);
    if(entry->type==FILE_SYMLINK)return -1;
    {int src=openat(stagefd,source_leaf,O_RDONLY|O_NOFOLLOW|O_CLOEXEC),dst;uint8_t buf[16384];ssize_t n;char hash[HASH_HEX];struct stat st;
        if(src<0)return -1;
        if(fstatat(parent,target_leaf,&existing,AT_SYMLINK_NOFOLLOW)==0){if(old_entry==NULL||verify_entry_at(ctx,parent,FILE_COUNT-1U,old_entry)!=0){close(src);errno=EEXIST;return -1;}}
        else if(errno!=ENOENT||old_entry!=NULL){close(src);return -1;}
        dst=openat(parent,tmp,O_RDWR|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0600);if(dst<0){close(src);return -1;}
        while((n=read(src,buf,sizeof(buf)))>0)if(write_all(dst,buf,(size_t)n)!=0){close(src);close(dst);unlinkat(parent,tmp,0);return -1;}
        if(n<0||fchown(dst,ctx->uid,ctx->gid)!=0||fchmod(dst,entry->mode)!=0||fsync(dst)!=0||hash_fd(dst,hash)!=0||strcmp(hash,entry->hash)!=0||fstat(dst,&st)!=0||!expected_mode(ctx,&st,entry->mode)){int e=errno?errno:EPERM;close(src);close(dst);unlinkat(parent,tmp,0);errno=e;return -1;}
        close(src);close(dst);
    }
    if(old_entry!=NULL){if(fstatat(parent,target_leaf,&existing,AT_SYMLINK_NOFOLLOW)!=0||verify_entry_at(ctx,parent,FILE_COUNT-1U,old_entry)!=0){unlinkat(parent,tmp,0);errno=EPERM;return -1;}}
    else if(fstatat(parent,target_leaf,&existing,AT_SYMLINK_NOFOLLOW)==0||errno!=ENOENT){unlinkat(parent,tmp,0);errno=EEXIST;return -1;}
    if(renameat(parent,tmp,parent,target_leaf)!=0){int e=errno;unlinkat(parent,tmp,0);errno=e;return -1;}return fsync_dir(parent);
}
static int manifests_equal(const struct manifest *a,const struct manifest *b)
{
    if(strcmp(a->project_version,b->project_version)||strcmp(a->package_generation,b->package_generation)||
       strcmp(a->backup_generation,b->backup_generation)||strcmp(a->signing_status,b->signing_status))return 0;
    for(size_t i=0;i<FILE_COUNT;++i)if(a->files[i].type!=b->files[i].type||a->files[i].mode!=b->files[i].mode||
       a->files[i].uid!=b->files[i].uid||a->files[i].gid!=b->files[i].gid||strcmp(a->files[i].hash,b->files[i].hash))return 0;
    return 1;
}
static int commit_staged(struct context *ctx,const char *stage_generation,struct manifest *m,const struct manifest *old_manifest)
{
    int stagefd;struct manifest check;
#if defined(IU_INSTALLER_TESTING)
    test_commit_count=0;
#endif
    stagefd=openat(ctx->stagingfd,stage_generation,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);if(stagefd<0)return -1;
    if(stage_manifest_text(stagefd,&check,ctx)!=0||!manifests_equal(&check,m)){close(stagefd);errno=EBADMSG;return -1;}
    for(size_t i=0;i<FILE_COUNT;++i){if(i==7U)continue;
        if(install_one_from_stage(ctx,stagefd,i,&m->files[i],old_manifest==NULL?NULL:&old_manifest->files[i])!=0){close(stagefd);return -1;}
        if(verify_entry_at(ctx,parent_for_index(ctx,i),i,&m->files[i])!=0){close(stagefd);errno=EIO;return -1;}
#if defined(IU_INSTALLER_TESTING)
        ++test_commit_count;
        maybe_interrupt("commit");
#endif
    }
    if(write_install_manifest(ctx,m)!=0){close(stagefd);return -1;}
    /* The disabled schema-v1 state record is written last. */
    if(stage_copy_out(stagefd,"f7",ctx->datafd,"install-state",ctx,&m->files[7],old_manifest==NULL?NULL:&old_manifest->files[7])!=0){close(stagefd);return -1;}
    if(fsync_dir(ctx->datafd)!=0||verify_state_reader(ctx)!=0){close(stagefd);errno=EIO;return -1;}
    close(stagefd);return 0;
}

static int remove_owned_file(struct context *ctx,size_t index,const struct manifest_entry *entry)
{
    int parent=parent_for_index(ctx,index);
    if(verify_entry_at(ctx,parent,index,entry)!=0){errno=EPERM;return -1;}
    if(unlinkat(parent,FILES[index].leaf,0)!=0)return -1;
    return fsync_dir(parent);
}
static int is_private_temp_name(const char *name)
{
    static const char *prefixes[]={".tmp-",".iu-tmp-",".iu-meta-",".iu-restore-",".iu-state-"};
    const char *tail=NULL;size_t i;int previous_dash=1;
    for(i=0;i<sizeof(prefixes)/sizeof(prefixes[0]);++i){size_t n=strlen(prefixes[i]);if(strncmp(name,prefixes[i],n)==0){tail=name+n;break;}}
    if(tail==NULL||*tail=='\0')return 0;
    for(;*tail;++tail){if(*tail=='-'){if(previous_dash)return 0;previous_dash=1;}else if(*tail>='0'&&*tail<='9')previous_dash=0;else return 0;}
    return !previous_dash;
}
static int cleanup_private_temps(struct context *ctx,int dirfd)
{
    int copy=openat(dirfd,".",O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);DIR *dir;struct dirent *entry;int changed=0;if(copy<0)return -1;dir=fdopendir(copy);if(!dir){close(copy);return -1;}
    while((entry=readdir(dir))!=NULL){struct stat st;if(!is_private_temp_name(entry->d_name))continue;
        if(fstatat(dirfd,entry->d_name,&st,AT_SYMLINK_NOFOLLOW)!=0){closedir(dir);return -1;}
        if(!stat_expected(ctx,&st)||(st.st_mode&0077)!=0||
           (S_ISREG(st.st_mode)&&st.st_nlink!=1)||(!S_ISREG(st.st_mode)&&!S_ISLNK(st.st_mode))){closedir(dir);return -1;}
        if(S_ISLNK(st.st_mode)){char target[PATH_MAX];ssize_t n=readlinkat(dirfd,entry->d_name,target,sizeof(target)-1U);if(n<0){closedir(dir);return -1;}target[n]='\0';if(strcmp(target,FILES[1].link_target)!=0){closedir(dir);return -1;}}
        if(unlinkat(dirfd,entry->d_name,0)!=0){closedir(dir);return -1;}changed=1;
    }
    closedir(dir);return changed?fsync_dir(dirfd):0;
}
static int restore_backup(struct context *ctx,const char *generation,const char *recovery_generation,const struct manifest *alternate)
{
    int backupfd=-1,filesfd=-1;struct manifest m;char text[MAX_META_BYTES];size_t len;struct stat st;
    if(load_backup(ctx,generation,&m,&backupfd)!=0)return -1;
    filesfd=openat(backupfd,"files",O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);if(filesfd<0){close(backupfd);return -1;}
    if(strcmp(recovery_generation,"none")!=0)strcpy(m.backup_generation,recovery_generation);
    /* Restore data files individually. Each rename is atomic, while the journal
     * makes a power loss between destinations recoverable from its own snapshot. */
    for(size_t i=0;i<FILE_COUNT;++i){int parent=parent_for_index(ctx,i);char source[8],tmp[96];struct stat now;static unsigned counter;
        snprintf(source,sizeof(source),"f%zu",i);snprintf(tmp,sizeof(tmp),".iu-restore-%ld-%zu-%u",(long)getpid(),i,++counter);
        if(i==7U)continue;
        if(fstatat(parent,FILES[i].leaf,&now,AT_SYMLINK_NOFOLLOW)==0){
            int matches=verify_entry_at(ctx,parent,i,&m.files[i])==0;
            if(!matches&&alternate!=NULL)matches=verify_entry_at(ctx,parent,i,&alternate->files[i])==0;
            if(!matches){close(filesfd);close(backupfd);errno=EPERM;return -1;}
        }else if(errno!=ENOENT){close(filesfd);close(backupfd);return -1;}
        if(FILES[i].type==FILE_SYMLINK){if(symlinkat(FILES[i].link_target,parent,tmp)!=0||fchownat(parent,tmp,ctx->uid,ctx->gid,AT_SYMLINK_NOFOLLOW)!=0){close(filesfd);close(backupfd);return -1;}}
        else{int src=openat(filesfd,source,O_RDONLY|O_NOFOLLOW|O_CLOEXEC),dst;uint8_t buf[16384];ssize_t n;char hash[HASH_HEX];
            if(src<0){close(filesfd);close(backupfd);return -1;}dst=openat(parent,tmp,O_RDWR|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0600);if(dst<0){close(src);close(filesfd);close(backupfd);return -1;}
            while((n=read(src,buf,sizeof(buf)))>0)if(write_all(dst,buf,(size_t)n)!=0){close(src);close(dst);close(filesfd);close(backupfd);return -1;}
            if(n<0||fchown(dst,ctx->uid,ctx->gid)!=0||fchmod(dst,m.files[i].mode)!=0||fsync(dst)!=0||hash_fd(dst,hash)!=0||strcmp(hash,m.files[i].hash)!=0){close(src);close(dst);close(filesfd);close(backupfd);return -1;}close(src);close(dst);
        }
        if(renameat(parent,tmp,parent,FILES[i].leaf)!=0){int e=errno;unlinkat(parent,tmp,0);close(filesfd);close(backupfd);errno=e;return -1;}if(fsync_dir(parent)!=0){close(filesfd);close(backupfd);return -1;}
    }
    if(make_manifest_text(&m,text,sizeof(text),0,NULL,&len)!=0||write_atomic(ctx->datafd,"install-manifest",text,len,ctx,0600)!=0){close(filesfd);close(backupfd);return -1;}
    {int src=openat(filesfd,"f7",O_RDONLY|O_NOFOLLOW|O_CLOEXEC),dst;uint8_t buf[256];ssize_t n;char temp[80];static unsigned counter;
        snprintf(temp,sizeof(temp),".iu-state-%ld-%u",(long)getpid(),++counter);if(src<0){close(filesfd);close(backupfd);return -1;}
        dst=openat(ctx->datafd,temp,O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0600);if(dst<0){close(src);close(filesfd);close(backupfd);return -1;}
        while((n=read(src,buf,sizeof(buf)))>0)if(write_all(dst,buf,(size_t)n)!=0){close(src);close(dst);close(filesfd);close(backupfd);return -1;}
        if(n<0||fchown(dst,ctx->uid,ctx->gid)!=0||fchmod(dst,0600)!=0||fsync(dst)!=0){close(src);close(dst);close(filesfd);close(backupfd);return -1;}close(src);close(dst);
        if(fstatat(ctx->datafd,"install-state",&st,AT_SYMLINK_NOFOLLOW)==0){
            int matches=verify_entry_at(ctx,ctx->datafd,7,&m.files[7])==0;
            if(!matches&&alternate!=NULL)matches=verify_entry_at(ctx,ctx->datafd,7,&alternate->files[7])==0;
            if(!matches){unlinkat(ctx->datafd,temp,0);close(filesfd);close(backupfd);return -1;}}
        else if(errno!=ENOENT){unlinkat(ctx->datafd,temp,0);close(filesfd);close(backupfd);return -1;}
        if(renameat(ctx->datafd,temp,ctx->datafd,"install-state")!=0){int e=errno;unlinkat(ctx->datafd,temp,0);close(filesfd);close(backupfd);errno=e;return -1;}
    }
    close(filesfd);close(backupfd);return fsync_dir(ctx->datafd)==0&&verify_state_reader(ctx)==0?0:-1;
}
static int remove_install_contents(struct context *ctx,const struct manifest *m)
{
    /* State is last so readers see either the old complete install marker or no
     * marker. The transaction journal remains available until it is removed. */
    for(size_t i=0;i<FILE_COUNT-1U;++i)if(remove_owned_file(ctx,i,&m->files[i])!=0)return -1;
    if(unlinkat(ctx->datafd,"install-manifest",0)!=0)return -1;
    if(remove_owned_file(ctx,FILE_COUNT-1U,&m->files[FILE_COUNT-1U])!=0)return -1;
    return 0;
}
static int cleanup_stage(struct context *ctx,const char *generation)
{
    int dirfd;struct stat st;char leaf[8];
    if(!safe_generation(generation))return -1;
    dirfd=openat(ctx->stagingfd,generation,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);if(dirfd<0)return errno==ENOENT?0:-1;
    if(fstat(dirfd,&st)!=0||!expected_mode(ctx,&st,0700)){close(dirfd);return -1;}
    for(size_t i=0;i<FILE_COUNT;++i){struct stat fs;snprintf(leaf,sizeof(leaf),"f%zu",i);if(fstatat(dirfd,leaf,&fs,AT_SYMLINK_NOFOLLOW)==0){if(!stat_expected(ctx,&fs)||(S_ISREG(fs.st_mode)&&fs.st_nlink!=1)||(!S_ISREG(fs.st_mode)&&!S_ISLNK(fs.st_mode))){close(dirfd);return -1;}if(unlinkat(dirfd,leaf,0)!=0){close(dirfd);return -1;}}else if(errno!=ENOENT){close(dirfd);return -1;}}
    if(fstatat(dirfd,"manifest",&st,AT_SYMLINK_NOFOLLOW)==0){if(!S_ISREG(st.st_mode)||st.st_nlink!=1||!expected_mode(ctx,&st,0600)||unlinkat(dirfd,"manifest",0)!=0){close(dirfd);return -1;}}else if(errno!=ENOENT){close(dirfd);return -1;}
    if(fstatat(dirfd,"backup-manifest",&st,AT_SYMLINK_NOFOLLOW)==0){if(!S_ISREG(st.st_mode)||st.st_nlink!=1||!expected_mode(ctx,&st,0600)||unlinkat(dirfd,"backup-manifest",0)!=0){close(dirfd);return -1;}}else if(errno!=ENOENT){close(dirfd);return -1;}
    {int filesfd=openat(dirfd,"files",O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);if(filesfd>=0){for(size_t i=0;i<FILE_COUNT;++i){struct stat fs;snprintf(leaf,sizeof(leaf),"f%zu",i);if(fstatat(filesfd,leaf,&fs,AT_SYMLINK_NOFOLLOW)==0){if(!stat_expected(ctx,&fs)||(S_ISREG(fs.st_mode)&&fs.st_nlink!=1)||(!S_ISREG(fs.st_mode)&&!S_ISLNK(fs.st_mode))||unlinkat(filesfd,leaf,0)!=0){close(filesfd);close(dirfd);return -1;}}else if(errno!=ENOENT){close(filesfd);close(dirfd);return -1;}}
            if(unlinkat(dirfd,"files",AT_REMOVEDIR)!=0){close(filesfd);close(dirfd);return -1;}close(filesfd);}else if(errno!=ENOENT){close(dirfd);return -1;}}
    if(cleanup_private_temps(ctx,dirfd)!=0){close(dirfd);return -1;}
    close(dirfd);if(unlinkat(ctx->stagingfd,generation,AT_REMOVEDIR)!=0)return -1;return fsync_dir(ctx->stagingfd);
}
static int clean_all_staging(struct context *ctx)
{
    int dupfd;DIR *dir;struct dirent *de;char **names=NULL;size_t count=0,capacity=0;
    if(ctx->stagingfd<0)return 0;
    dupfd=openat(ctx->stagingfd,".",O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);if(dupfd<0)return -1;dir=fdopendir(dupfd);if(!dir){close(dupfd);return -1;}
    while((de=readdir(dir))!=NULL){if(strcmp(de->d_name,".")==0||strcmp(de->d_name,"..")==0)continue;
        if(!safe_generation(de->d_name)){closedir(dir);return -1;}
        if(count==capacity){size_t next=capacity?capacity*2U:8U;char **grown=realloc(names,next*sizeof(*names));if(!grown){closedir(dir);return -1;}names=grown;capacity=next;}
        names[count]=strdup(de->d_name);if(names[count]==NULL){closedir(dir);return -1;}++count;
    }
    closedir(dir);
    for(size_t i=0;i<count;++i){if(cleanup_stage(ctx,names[i])!=0){for(size_t j=i;j<count;++j)free(names[j]);free(names);return -1;}free(names[i]);}
    free(names);return 0;
}
static int directory_empty(int fd)
{
    int copy=openat(fd,".",O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);DIR *dir;struct dirent *entry;if(copy<0)return -1;dir=fdopendir(copy);if(!dir){close(copy);return -1;}
    while((entry=readdir(dir))!=NULL){if(strcmp(entry->d_name,".")&&strcmp(entry->d_name,"..")){closedir(dir);return 0;}}
    closedir(dir);return 1;
}
static int data_has_only_staging_and_backups(int fd)
{
    int copy=openat(fd,".",O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);DIR *dir;struct dirent *entry;int saw_backups=0,saw_staging=0;if(copy<0)return -1;dir=fdopendir(copy);if(!dir){close(copy);return -1;}
    while((entry=readdir(dir))!=NULL){if(!strcmp(entry->d_name,".")||!strcmp(entry->d_name,".."))continue;
        if(!strcmp(entry->d_name,"backups")&&!saw_backups)saw_backups=1;
        else if(!strcmp(entry->d_name,"staging")&&!saw_staging)saw_staging=1;
        else{closedir(dir);return 0;}}
    closedir(dir);return saw_backups&&saw_staging;
}
static int remove_empty_uninstalled_data(struct context *ctx)
{
    struct stat st;int empty;
    if(ctx->datafd<0)return 0;
    if(fstatat(ctx->datafd,"install-manifest",&st,AT_SYMLINK_NOFOLLOW)==0)return 0;
    if(errno!=ENOENT)return -1;
    for(size_t i=0;i<FILE_COUNT;++i){int parent=parent_for_index(ctx,i);if(fstatat(parent,FILES[i].leaf,&st,AT_SYMLINK_NOFOLLOW)==0)return 0;if(errno!=ENOENT)return -1;}
    empty=directory_empty(ctx->backupsfd);if(empty!=1)return empty<0?-1:0;
    empty=directory_empty(ctx->stagingfd);if(empty!=1)return empty<0?-1:0;
    empty=data_has_only_staging_and_backups(ctx->datafd);if(empty!=1)return empty<0?-1:0;
    if(unlinkat(ctx->datafd,"backups",AT_REMOVEDIR)!=0||unlinkat(ctx->datafd,"staging",AT_REMOVEDIR)!=0)return -1;
    close(ctx->stagingfd);ctx->stagingfd=-1;close(ctx->backupsfd);ctx->backupsfd=-1;close(ctx->datafd);ctx->datafd=-1;
    if(unlinkat(ctx->varlibfd,"ios-unsandboxed",AT_REMOVEDIR)!=0)return -1;
    return fsync_dir(ctx->varlibfd);
}
static int clear_transaction(struct context *ctx)
{
    struct stat st;if(fstatat(ctx->datafd,"transaction",&st,AT_SYMLINK_NOFOLLOW)!=0)return errno==ENOENT?0:-1;
    if(!S_ISREG(st.st_mode)||st.st_nlink!=1||!expected_mode(ctx,&st,0600))return -1;
    if(unlinkat(ctx->datafd,"transaction",0)!=0)return -1;
    return fsync_dir(ctx->datafd);
}
static int recover_transaction(struct context *ctx,const struct transaction *t)
{
    if(strcmp(t->recovery_generation,"none")!=0){
        struct manifest snapshot,alternate;int backupfd=-1,stagefd=-1;const struct manifest *alternate_ptr=NULL;
        if(load_backup(ctx,t->recovery_generation,&snapshot,&backupfd)!=0)return bad("recovery backup is missing, incomplete, or corrupt");
        close(backupfd);
        if(strcmp(t->staging_generation,"none")!=0){
            stagefd=openat(ctx->stagingfd,t->staging_generation,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
            if(stagefd>=0){if(stage_manifest_text(stagefd,&alternate,ctx)==0)alternate_ptr=&alternate;close(stagefd);}
        }
        if(restore_backup(ctx,t->recovery_generation,"none",alternate_ptr)!=0)return bad("could not restore the verified pre-transaction backup; journal retained");
    }else{
        /* First-install interruption: remove only paths matching the staged,
         * package-verified installation. Conflicting edits are preserved. */
        int stagefd;struct manifest staged;
        if(!safe_generation(t->staging_generation))return bad("initial-install journal has no safe staging generation");
        stagefd=openat(ctx->stagingfd,t->staging_generation,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);if(stagefd<0)return bad("initial-install recovery staging is missing");
        if(stage_manifest_text(stagefd,&staged,ctx)!=0){close(stagefd);return bad("initial-install recovery metadata is corrupt");}
        for(size_t i=0;i<FILE_COUNT-1U;++i){struct stat st;int parent=parent_for_index(ctx,i);if(fstatat(parent,FILES[i].leaf,&st,AT_SYMLINK_NOFOLLOW)==0){if(verify_entry_at(ctx,parent,i,&staged.files[i])!=0){close(stagefd);return bad("recovery found a modified or foreign destination; it was preserved");}if(unlinkat(parent,FILES[i].leaf,0)!=0){close(stagefd);return bad("could not remove a verified partial first-install file");}}else if(errno!=ENOENT){close(stagefd);return bad("could not safely inspect a partial first-install destination");}}
        {struct stat st;if(fstatat(ctx->datafd,"install-manifest",&st,AT_SYMLINK_NOFOLLOW)==0){if(!S_ISREG(st.st_mode)||st.st_nlink!=1||!expected_mode(ctx,&st,0600)||unlinkat(ctx->datafd,"install-manifest",0)!=0){close(stagefd);return bad("partial manifest is modified or unsafe; preserved");}}}
        {struct stat st;if(fstatat(ctx->datafd,"install-state",&st,AT_SYMLINK_NOFOLLOW)==0){if(verify_entry_at(ctx,ctx->datafd,7,&staged.files[7])!=0||unlinkat(ctx->datafd,"install-state",0)!=0){close(stagefd);return bad("partial disabled state is modified or unsafe; preserved");}}else if(errno!=ENOENT){close(stagefd);return bad("could not safely inspect partial state");}}
        close(stagefd);
    }
    if(strcmp(t->staging_generation,"none")!=0&&cleanup_stage(ctx,t->staging_generation)!=0)return bad("recovered files, but could not safely clean staging");
    if(cleanup_private_temps(ctx,ctx->bindirfd)!=0||cleanup_private_temps(ctx,ctx->datafd)!=0)return bad("recovered files, but transaction temporary files were unsafe");
    if(clear_transaction(ctx)!=0)return bad("recovery completed but its journal could not be removed");
    if(strcmp(t->recovery_generation,"none")==0&&remove_empty_uninstalled_data(ctx)!=0)return bad("initial-install recovery left an unsafe or non-empty project data directory");
    printf("Recovery complete: previous verified installation generation restored.\n");return 0;
}

static int check_existing_install(struct context *ctx,struct manifest *m)
{
    int result=load_manifest_fd(ctx,m);
    if(result==1)return 1;
    if(result!=0)return -1;
    if(verify_state_reader(ctx)!=0)return -1;
    return 0;
}
static int check_no_transaction(struct context *ctx)
{
    struct transaction t;int r=load_transaction(ctx,&t);
    if(r==0)return bad("an interrupted transaction is recorded; run recover --apply first");
    if(r<0)return bad("transaction journal is unsafe or corrupt; preserve it for review");
    return 0;
}
static int check_destination_conflicts(struct context *ctx)
{
    if(ctx->datafd>=0)return bad("project data directory already exists without a valid installation manifest; refusing to adopt it");
    for(size_t i=0;i<3U;++i)if(ensure_absent(ctx,i)!=0)return bad("a destination path is already occupied; refusing to overwrite a foreign file");
    return 0;
}
static int check_production_permissions(struct context *ctx)
{
    if(!ctx->fixture){struct stat st;int fd=open("/var/log",O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);if(fd<0)return bad("rootful /var/log is unavailable");
        if(fstat(fd,&st)!=0||!mode_safe_dir(&st)||!stat_expected(ctx,&st)){close(fd);return bad("/var/log ownership or permissions are unsafe");}close(fd);}
    return 0;
}
static int active_plist_present(struct context *ctx)
{
    struct stat st;
    if(ctx->fixture){int launchd=open_fixture_subdir(ctx->rootfd,"Library/LaunchDaemons");if(launchd<0)return errno==ENOENT?0:-1;
        if(fstatat(launchd,"com.ios-unsandboxed.daemon.plist",&st,AT_SYMLINK_NOFOLLOW)==0){close(launchd);return 1;}
        close(launchd);return errno==ENOENT?0:-1;}
    if(lstat("/Library/LaunchDaemons/com.ios-unsandboxed.daemon.plist",&st)==0)return 1;
    return errno==ENOENT?0:-1;
}

static int service_lifecycle_metadata_present(struct context *ctx)
{
    static const char *names[]={"service-registration","service-transaction"};struct stat st;
    if(ctx->datafd<0)return 0;
    for(size_t i=0;i<sizeof(names)/sizeof(names[0]);++i){
        if(fstatat(ctx->datafd,names[i],&st,AT_SYMLINK_NOFOLLOW)==0)return 1;
        if(errno!=ENOENT)return -1;
    }
    return 0;
}

static int cmd_status(struct context *ctx)
{
    struct manifest m;struct transaction t;int current=check_existing_install(ctx,&m);int txn=load_transaction(ctx,&t);int active;
    if(txn<0)return bad("transaction journal is corrupt or unsafe");
    if(txn==0)printf("Transaction: interrupted (%s, phase %s). Run recover --apply.\n",t.action,t.phase);
    if(current==1){printf("Installation: not installed\n");return txn==0?3:0;}
    if(current<0)return bad("installation manifest, owned files, or disabled state failed verification");
    active=active_plist_present(ctx);if(active<0)return bad("active LaunchDaemon path cannot be inspected safely");
    printf("Installation: verified\nProject version: %s\nPackage generation: %s\nSigning status: %s\nBackup generation: %s\nExecution activation: disabled (schema v1)\nStaged LaunchDaemon plist: verified inactive template\nActive LaunchDaemon plist: %s (launchd state not queried)\n",m.project_version,m.package_generation,m.signing_status,m.backup_generation,active?"present":"absent");
    return txn==0?3:0;
}
static int cmd_maintenance_plan(struct context *ctx,const char *command)
{
    struct manifest current;int active=0,service_metadata=0;int existing=check_existing_install(ctx,&current);
    if(check_no_transaction(ctx)!=0)return 3;
    if(existing==1){if(strcmp(command,"uninstall")==0){puts("Uninstall plan: no verified installation is present; remaining files will be preserved.");return 0;}return bad("rollback requires a verified installation");}
    if(existing<0)return bad("current installation is modified, foreign, or unsupported");
    service_metadata=service_lifecycle_metadata_present(ctx);if(service_metadata<0)return bad("service lifecycle metadata cannot be inspected safely");
    active=active_plist_present(ctx);if(active<0)return bad("active LaunchDaemon path cannot be inspected safely");
    if(strcmp(command,"rollback")==0){struct manifest previous;int backupfd=-1;
        if(active||service_metadata)return bad("stop and unregister the project service before rollback");
        if(strcmp(current.backup_generation,"none")==0)return bad("no verified rollback generation is recorded");
        if(load_backup(ctx,current.backup_generation,&previous,&backupfd)!=0)return bad("rollback backup is missing or corrupt");
        close(backupfd);
        printf("Rollback plan: restore version %s from verified generation %s.\n",previous.project_version,current.backup_generation);return 0;}
    if(active||service_metadata)return bad("stop and unregister the project service before uninstall");
    puts("Uninstall plan: remove the eight verified project-owned files and state after preserving a recovery generation.");
    puts("Existing LaunchDaemon registration is not removed, and launchctl is not invoked.");return 0;
}
static int cmd_plan(struct context *ctx,const char *action,const char *package_path)
{
    struct package pkg;struct manifest current;int existing=check_existing_install(ctx,&current);
    if(check_no_transaction(ctx)!=0)return 3;
    if(strcmp(action,"upgrade")==0){int active=active_plist_present(ctx),metadata=service_lifecycle_metadata_present(ctx);if(active<0||metadata<0)return bad("service lifecycle ownership state cannot be inspected safely");if(active||metadata)return bad("unregister the project service before upgrading its daemon binary");}
    if(existing<0)return bad("current installation is modified, foreign, or unsupported");
    if(verify_package_directory(ctx,package_path,&pkg)!=0)return bad("package is missing, malformed, has a bad checksum, or is not an iOS ARM64 package");
    if(strcmp(action,"install")==0){if(existing==0){close(pkg.dirfd);return bad("installation already exists; use upgrade");}if(check_destination_conflicts(ctx)!=0){close(pkg.dirfd);return 3;}
        printf("Plan: install version %s (%s signing status)\n",pkg.version,pkg.signing);
    }else{
        if(existing!=0){close(pkg.dirfd);return bad("upgrade requires a verified schema-v1 installation");}
        if(version_cmp(pkg.version,current.project_version)<=0){close(pkg.dirfd);return bad("upgrade package version must be newer than the installed version");}
        printf("Plan: upgrade %s to %s; verified backup generation will be retained\n",current.project_version,pkg.version);
    }
    printf("Files: CLI, daemon, iu symlink, manager, installer helper, paths contract, disabled schema-v1 state\n");
    printf("LaunchDaemon: stored as /var/lib/ios-unsandboxed/com.ios-unsandboxed.daemon.plist.inactive; not registered\n");
    printf("No filesystem changes. Use %s --package PACKAGE --apply to commit.\n",action);
    close(pkg.dirfd);return 0;
}
static int cmd_install_or_upgrade(struct context *ctx,const char *action,const char *package_path)
{
    struct package pkg;struct manifest current,newm;struct transaction transaction;char stagegen[80],backupgen[80];int existing;
    if(check_production_platform(ctx)!=0||check_production_permissions(ctx)!=0)return 2;
    if(acquire_lock(ctx)!=0)return 4;
    if(ctx->datafd<0){struct stat st;if(fstatat(ctx->varlibfd,"ios-unsandboxed",&st,AT_SYMLINK_NOFOLLOW)==0){fail("project data directory exists without a verified manifest");return 3;}if(errno!=ENOENT)return bad("cannot safely inspect project data path");}
    if(check_no_transaction(ctx)!=0)return 3;
    existing=check_existing_install(ctx,&current);
    if(existing<0)return bad("current installation is modified, foreign, or unsupported");
    if(strcmp(action,"install")==0){if(existing==0)return bad("installation already exists; use upgrade");if(check_destination_conflicts(ctx)!=0)return 3;}
    else {int active=active_plist_present(ctx),metadata=service_lifecycle_metadata_present(ctx);if(active<0||metadata<0)return bad("service lifecycle ownership state cannot be inspected safely");if(active||metadata)return bad("unregister the project service before upgrading its daemon binary");if(existing!=0)return bad("upgrade requires a verified schema-v1 installation");}
    if(verify_package_directory(ctx,package_path,&pkg)!=0)return bad("package validation failed (integrity, metadata, ownership, Mach-O architecture, or plist contract)");
    if(existing==0&&version_cmp(pkg.version,current.project_version)<=0){close(pkg.dirfd);return bad("upgrade package version must be newer than installed version");}
    if(ensure_project_data(ctx)!=0){close(pkg.dirfd);return bad("could not create a private project data directory");}
    if(create_generation(stagegen)!=0||stage_package(ctx,&pkg,stagegen,&newm)!=0){close(pkg.dirfd);return bad("could not stage and verify package payloads");}
#if defined(IU_INSTALLER_TESTING)
    test_active_action=action;
    maybe_interrupt("staging");
#endif
    if(existing==0){if(create_transaction_backup(ctx,&current,backupgen)!=0){close(pkg.dirfd);return bad("could not create a verified backup generation");}strcpy(newm.backup_generation,backupgen);}
    else strcpy(backupgen,"none");
    {int sfd=openat(ctx->stagingfd,stagegen,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);char text[MAX_META_BYTES];size_t n;
        if(sfd<0){close(pkg.dirfd);return bad("staging directory disappeared");}
        if(make_manifest_text(&newm,text,sizeof(text),0,NULL,&n)!=0||write_atomic(sfd,"manifest",text,n,ctx,0600)!=0){close(sfd);close(pkg.dirfd);return bad("could not write staged ownership manifest");}close(sfd);}
    memset(&transaction,0,sizeof(transaction));strcpy(transaction.action,action);strcpy(transaction.recovery_generation,backupgen);strcpy(transaction.target_generation,"none");strcpy(transaction.staging_generation,stagegen);strcpy(transaction.package_generation,pkg.manifest_hash);strcpy(transaction.phase,"prepared");
    if(write_transaction(ctx,&transaction)!=0){close(pkg.dirfd);return bad("could not persist the transaction journal");}
#if defined(IU_INSTALLER_TESTING)
    maybe_interrupt("prepared");
#endif
    strcpy(transaction.phase,"committing");if(write_transaction(ctx,&transaction)!=0){close(pkg.dirfd);return bad("could not advance the transaction journal");}
    if(commit_staged(ctx,stagegen,&newm,existing==0?&current:NULL)!=0){close(pkg.dirfd);return bad("commit stopped; transaction journal and verified backup are retained; run recover --apply");}
    strcpy(transaction.phase,"state_written");(void)write_transaction(ctx,&transaction);
    if(cleanup_stage(ctx,stagegen)!=0||clear_transaction(ctx)!=0){close(pkg.dirfd);return bad("installation committed, but journal cleanup is incomplete; inspect status and run recover --apply if reported");}
    printf("%s complete: version %s; signing status %s; execution activation disabled.\n",strcmp(action,"install")==0?"Install":"Upgrade",pkg.version,pkg.signing);
    printf("The LaunchDaemon plist remains staged inactive; no service was registered or started.\n");close(pkg.dirfd);return 0;
}
static int cmd_rollback(struct context *ctx)
{
    struct manifest current,backup;struct transaction transaction;char recovery[80],stagegen[80];int backupfd=-1;
    if(check_production_platform(ctx)!=0)return 2;
    if(acquire_lock(ctx)!=0)return 4;
    if(check_no_transaction(ctx)!=0)return 3;
    if(check_existing_install(ctx,&current)!=0)return bad("rollback requires a fully verified current installation");
    {int active=active_plist_present(ctx),metadata=service_lifecycle_metadata_present(ctx);if(active<0||metadata<0)return bad("service lifecycle ownership state cannot be inspected safely");if(active||metadata)return bad("stop and unregister the project service before rollback");}
    if(strcmp(current.backup_generation,"none")==0)return bad("no verified rollback generation is recorded");
    if(load_backup(ctx,current.backup_generation,&backup,&backupfd)!=0)return bad("rollback backup is missing, corrupt, incomplete, or has unexpected ownership/mode");
    close(backupfd);
    if(create_transaction_backup(ctx,&current,recovery)!=0)return bad("could not preserve the current generation for interrupted-rollback recovery");
    if(create_generation(stagegen)!=0||stage_backup(ctx,current.backup_generation,stagegen,&backup,recovery)!=0)return bad("could not stage the verified rollback generation");
#if defined(IU_INSTALLER_TESTING)
    test_active_action="rollback";
#endif
    memset(&transaction,0,sizeof(transaction));strcpy(transaction.action,"rollback");strcpy(transaction.recovery_generation,recovery);strcpy(transaction.target_generation,current.backup_generation);strcpy(transaction.staging_generation,stagegen);strcpy(transaction.package_generation,backup.package_generation);strcpy(transaction.phase,"prepared");
    if(write_transaction(ctx,&transaction)!=0)return bad("could not persist rollback journal");
#if defined(IU_INSTALLER_TESTING)
    maybe_interrupt("prepared");
#endif
    strcpy(transaction.phase,"committing");(void)write_transaction(ctx,&transaction);
    if(commit_staged(ctx,stagegen,&backup,&current)!=0)return bad("rollback stopped; the current generation is retained as recovery backup; run recover --apply");
    strcpy(transaction.phase,"state_written");(void)write_transaction(ctx,&transaction);
    if(cleanup_stage(ctx,stagegen)!=0||clear_transaction(ctx)!=0)return bad("rollback committed but cleanup is incomplete");
    printf("Rollback complete: restored verified generation %s (version %s).\n",current.backup_generation,backup.project_version);
    printf("This restores filesystem artifacts only; no kernel, trust-cache, vnode-signing, or process sandbox changes are involved.\n");return 0;
}

static int remove_backup_tree(struct context *ctx,const char *generation)
{
    int backupfd=-1,filesfd=-1;struct manifest m;char leaf[8];struct stat st;
    if(load_backup(ctx,generation,&m,&backupfd)!=0)return -1;
    filesfd=openat(backupfd,"files",O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);if(filesfd<0){close(backupfd);return -1;}
    for(size_t i=0;i<FILE_COUNT;++i){snprintf(leaf,sizeof(leaf),"f%zu",i);if(unlinkat(filesfd,leaf,0)!=0){close(filesfd);close(backupfd);return -1;}}
    if(unlinkat(backupfd,"backup-manifest",0)!=0){close(filesfd);close(backupfd);return -1;}close(filesfd);
    if(unlinkat(backupfd,"files",AT_REMOVEDIR)!=0){close(backupfd);return -1;}close(backupfd);
    if(fstatat(ctx->backupsfd,generation,&st,AT_SYMLINK_NOFOLLOW)!=0||!S_ISDIR(st.st_mode)||!expected_mode(ctx,&st,0700)||unlinkat(ctx->backupsfd,generation,AT_REMOVEDIR)!=0)return -1;
    return fsync_dir(ctx->backupsfd);
}
static int clean_all_backups(struct context *ctx)
{
    int dupfd=openat(ctx->backupsfd,".",O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);DIR *dir;struct dirent *de;char **names=NULL;size_t count=0,cap=0;
    if(dupfd<0)return -1;
    dir=fdopendir(dupfd);if(!dir){close(dupfd);return -1;}
    while((de=readdir(dir))!=NULL){if(strcmp(de->d_name,".")==0||strcmp(de->d_name,"..")==0)continue;if(!safe_generation(de->d_name)){closedir(dir);return -1;}
        if(count==cap){size_t nc=cap?cap*2U:8U;char **nn=realloc(names,nc*sizeof(*names));if(!nn){closedir(dir);return -1;}names=nn;cap=nc;}names[count]=strdup(de->d_name);if(!names[count++]){closedir(dir);return -1;}}
    closedir(dir);for(size_t i=0;i<count;++i){if(remove_backup_tree(ctx,names[i])!=0){for(size_t j=i;j<count;++j)free(names[j]);free(names);return -1;}free(names[i]);}free(names);return 0;
}
static int cmd_uninstall(struct context *ctx)
{
    struct manifest current;struct transaction transaction;char recovery[80];int existing;
    if(check_production_platform(ctx)!=0)return 2;
    if(acquire_lock(ctx)!=0)return 4;
    if(check_no_transaction(ctx)!=0)return 3;
    existing=check_existing_install(ctx,&current);
    if(existing==1){printf("No verified installation manifest is present; leaving all remaining files untouched.\n");return 0;}
    if(existing!=0)return bad("uninstall requires every project-owned file and disabled state to verify");
    {int active=active_plist_present(ctx),metadata=service_lifecycle_metadata_present(ctx);if(active<0||metadata<0)return bad("service lifecycle ownership state cannot be inspected safely");if(active||metadata)return bad("stop and unregister the project service before uninstall");}
    if(create_transaction_backup(ctx,&current,recovery)!=0)return bad("could not preserve a verified uninstall recovery generation");
    memset(&transaction,0,sizeof(transaction));strcpy(transaction.action,"uninstall");strcpy(transaction.recovery_generation,recovery);strcpy(transaction.target_generation,"none");strcpy(transaction.staging_generation,"none");strcpy(transaction.package_generation,current.package_generation);strcpy(transaction.phase,"prepared");
    if(write_transaction(ctx,&transaction)!=0)return bad("could not persist uninstall journal");
#if defined(IU_INSTALLER_TESTING)
    test_active_action="uninstall";
    maybe_interrupt("prepared");
#endif
    strcpy(transaction.phase,"committing");(void)write_transaction(ctx,&transaction);
    if(remove_install_contents(ctx,&current)!=0)return bad("uninstall stopped safely; verified recovery backup and journal remain; run recover --apply");
    strcpy(transaction.phase,"state_written");(void)write_transaction(ctx,&transaction);
    if(clear_transaction(ctx)!=0)return bad("uninstall files were removed but the journal remains; run recover --apply");
    if(clean_all_backups(ctx)!=0)return bad("installation removed; one or more backup generations were unsafe and were preserved");
    if(clean_all_staging(ctx)!=0)return bad("installation removed; one or more staging entries were unsafe and were preserved");
    if(unlinkat(ctx->datafd,"staging",AT_REMOVEDIR)!=0||unlinkat(ctx->datafd,"backups",AT_REMOVEDIR)!=0||unlinkat(ctx->varlibfd,"ios-unsandboxed",AT_REMOVEDIR)!=0){
        printf("Uninstall complete; empty project directories remain because they contain unrecognized or in-use files.\n");return 0;}
    printf("Uninstall complete: verified project-owned files, state, backups, and staging removed.\n");
    return 0;
}

static int parse_arguments(int argc,char **argv,const char **command,const char **service_action,const char **package_path,const char **test_root,int *apply,int *confirmed,int *acknowledge)
{
    *command=NULL;*service_action=NULL;*package_path=NULL;*test_root=NULL;*apply=0;*confirmed=0;*acknowledge=0;
    if(argc<2)return -1;
    *command=argv[1];
    int first=2;
    if(strcmp(*command,"service")==0){if(argc<3)return -1;*service_action=argv[2];first=3;}
    for(int i=first;i<argc;++i){
        if(strcmp(argv[i],"--apply")==0){if(*apply)return -1;*apply=1;continue;}
        if(strcmp(argv[i],"--confirm")==0){if(*confirmed)return -1;*confirmed=1;continue;}
        if(strcmp(argv[i],"--acknowledge-run-at-load")==0){if(*acknowledge)return -1;*acknowledge=1;continue;}
        if(strcmp(argv[i],"--package")==0&&i+1<argc){if(*package_path)return -1;*package_path=argv[++i];continue;}
        if(strcmp(argv[i],"--test-root")==0&&i+1<argc){if(*test_root)return -1;*test_root=argv[++i];continue;}
#if defined(IU_INSTALLER_TESTING)
        if(strcmp(argv[i],"--test-interrupt-at")==0&&i+1<argc){if(test_interrupt_at)return -1;test_interrupt_at=argv[++i];continue;}
#endif
        return -1;
    }
    return 0;
}
static int init_context(struct context *ctx,const char *test_root,int require_root)
{
    struct stat st;char resolved[PATH_MAX];memset(ctx,0,sizeof(*ctx));ctx->rootfd=ctx->varlibfd=ctx->bindirfd=ctx->datafd=ctx->backupsfd=ctx->stagingfd=ctx->lockfd=-1;
#if !defined(IU_INSTALLER_TESTING)
    if(test_root!=NULL)return bad("--test-root is available only in the host fixture helper");
#endif
    if(test_root){
        char root_copy[PATH_MAX],*save=NULL,*part;size_t root_length=strlen(test_root);
        if(root_length>=sizeof(root_copy)||root_length==0||test_root[0]!='/'||strcmp(test_root,"/")==0||test_root[root_length-1]=='/')return bad("--test-root must be an existing absolute, private, non-symlink directory owned by this user (and cannot be /)");
        strcpy(root_copy,test_root);part=strtok_r(root_copy,"/",&save);
        while(part){if(strcmp(part,".")==0||strcmp(part,"..")==0)return bad("--test-root cannot contain dot or traversal components");part=strtok_r(NULL,"/",&save);}
        if(lstat(test_root,&st)!=0||!S_ISDIR(st.st_mode)||S_ISLNK(st.st_mode)||st.st_uid!=geteuid()||(st.st_mode&0022)!=0||realpath(test_root,resolved)==NULL){return bad("--test-root must be an existing absolute, private, non-symlink directory owned by this user (and cannot be /)");}
        if(strcmp(resolved,"/")==0)return bad("root / cannot be used as a fixture root");
        strcpy(ctx->root,resolved);ctx->fixture=1;ctx->uid=geteuid();ctx->gid=getegid();ctx->wheel_gid=ctx->gid;
    }else{
        if(require_root&&geteuid()!=0)return bad("effective UID 0 is required for production management");
        ctx->uid=0;{struct group *wheel=getgrnam("wheel");if(!wheel)return bad("wheel group is unavailable; production mutation refused");ctx->gid=wheel->gr_gid;ctx->wheel_gid=wheel->gr_gid;}
        strcpy(ctx->root,"/");
    }
    if(open_base_dirs(ctx)!=0)return bad("rootful base directories are missing, symlinked, foreign-owned, or writable by group/other");
    return 0;
}
static void print_help(void)
{
    puts("ios-unsandboxed rootful installer manager\n"
         "Usage: manager.sh COMMAND [--package DIR] [--test-root DIR] [--apply]\n\n"
         "Commands:\n"
         "  help       Show this help\n"
         "  version    Show project and manager format versions\n"
         "  plan       Validate package and show install/upgrade operations (read-only)\n"
         "  status     Verify the owned manifest and disabled schema-v1 state\n"
         "  install    Install a package; changes require --apply\n"
         "  upgrade    Upgrade a verified install; changes require --apply\n"
         "  rollback   Restore the last verified backup; changes require --apply\n"
         "  uninstall  Remove only verified project-owned files; requires --apply\n"
         "  recover    Restore the journal's verified pre-transaction generation\n\n"
         "  service plan|status|register|start|stop|unregister|recover\n"
         "             Read-only by default; changes require --apply --confirm\n"
         "             register also requires --acknowledge-run-at-load\n\n"
         "Fixture mode: --test-root ABSOLUTE_PRIVATE_DIRECTORY. It requires an isolated root; launchd calls require a test-only mock.\n"
         "Production mutation requires root, iPad4,4, iOS 12.5.7, and verified rootful paths.\n"
         "No command activates execution. Service registration is explicit and may start the daemon. No command supports force.");
}
int main(int argc,char **argv)
{
    const char *command,*service_action,*package_path,*test_root;int apply,confirmed,acknowledge,result=0,mutating=0,need_package=0,require_root=1;struct context ctx;
    if(parse_arguments(argc,argv,&command,&service_action,&package_path,&test_root,&apply,&confirmed,&acknowledge)!=0){print_help();return 2;}
    if(strcmp(command,"service")!=0&&(confirmed||acknowledge)){fail("service confirmation flags are valid only for service commands");return 2;}
#if defined(IU_INSTALLER_TESTING)
    if(test_interrupt_at!=NULL){
        if(test_root==NULL||!apply){fail("test interruption requires an explicit --test-root and --apply");return 2;}
        if(strcmp(test_interrupt_at,"staging")&&strcmp(test_interrupt_at,"prepared")&&strncmp(test_interrupt_at,"commit:",7)&&strncmp(test_interrupt_at,"rollback:",9)){fail("unknown test interruption phase");return 2;}
    }
#endif
    if(strcmp(command,"help")==0){if(argc!=2)return 2;print_help();return 0;}
    if(strcmp(command,"version")==0){if(argc!=2)return 2;puts("iOS-Unsandboxed 0.1.0\ninstaller manager format 1\npackage format 1\ninstall manifest schema 1\nstate schema 1 (execution_activation=disabled)");return 0;}
    if(strcmp(command,"plan")==0){if(!package_path||apply){fail("plan requires --package and is always read-only");return 2;}need_package=1;}
    else if(strcmp(command,"install")==0||strcmp(command,"upgrade")==0){if(!package_path){fail("install and upgrade require --package DIR");return 2;}need_package=1;mutating=apply;}
    else if(strcmp(command,"status")==0){if(package_path||apply)return 2;}
    else if(strcmp(command,"service")==0){if(package_path||!service_action)return 2;
        if(!strcmp(service_action,"plan")||!strcmp(service_action,"status")){if(apply||confirmed||acknowledge)return 2;}
        else if(!strcmp(service_action,"register")||!strcmp(service_action,"start")||!strcmp(service_action,"stop")||!strcmp(service_action,"unregister")||!strcmp(service_action,"recover")){mutating=apply;if(acknowledge&&strcmp(service_action,"register")!=0)return 2;}
        else return 2;}
    else if(strcmp(command,"rollback")==0||strcmp(command,"uninstall")==0||strcmp(command,"recover")==0){if(package_path){fail("this command does not accept --package");return 2;}mutating=apply;}
    else{fail("unknown command");print_help();return 2;}
    (void)need_package;
    if(init_context(&ctx,test_root,require_root)!=0)return 2;
    if(strcmp(command,"plan")==0){struct manifest m;int installed=check_existing_install(&ctx,&m);if(installed<0)result=bad("current installation is modified, foreign, or unsupported");else result=cmd_plan(&ctx,installed==0?"upgrade":"install",package_path);}
    else if(strcmp(command,"status")==0)result=cmd_status(&ctx);
    else if(strcmp(command,"service")==0){enum iu_service_action action;struct manifest manifest;int installed=check_existing_install(&ctx,&manifest);int daemon_valid=0,template_valid=0;
        if(strcmp(service_action,"plan")==0)action=IU_SERVICE_PLAN;else if(strcmp(service_action,"status")==0)action=IU_SERVICE_STATUS;
        else if(strcmp(service_action,"register")==0)action=IU_SERVICE_REGISTER;else if(strcmp(service_action,"start")==0)action=IU_SERVICE_START;
        else if(strcmp(service_action,"stop")==0)action=IU_SERVICE_STOP;else if(strcmp(service_action,"unregister")==0)action=IU_SERVICE_UNREGISTER;else action=IU_SERVICE_RECOVER;
        if(installed==0){daemon_valid=verify_entry_at(&ctx,ctx.bindirfd,2,&manifest.files[2])==0;template_valid=verify_entry_at(&ctx,ctx.datafd,6,&manifest.files[6])==0;}
        if(mutating&&!ctx.fixture&&(check_production_platform(&ctx)!=0||check_production_permissions(&ctx)!=0))result=3;
        else if(mutating&&acquire_lock(&ctx)!=0)result=4;
        else if(mutating&&check_no_transaction(&ctx)!=0)result=3;
        else result=iu_service_lifecycle_run(ctx.root,ctx.fixture,action,apply,confirmed,acknowledge,installed==0?1:installed==1?0:-1,daemon_valid,template_valid);
    }
    else if(strcmp(command,"install")==0||strcmp(command,"upgrade")==0){
        if(!apply){struct manifest m;int installed=check_existing_install(&ctx,&m);if(installed<0)result=bad("current installation is modified, foreign, or unsupported");
            else result=cmd_plan(&ctx,command,package_path);}
        else result=cmd_install_or_upgrade(&ctx,command,package_path);
    }else if(strcmp(command,"rollback")==0){if(!mutating)result=cmd_maintenance_plan(&ctx,"rollback");else result=cmd_rollback(&ctx);}
    else if(strcmp(command,"uninstall")==0){if(!mutating)result=cmd_maintenance_plan(&ctx,"uninstall");else result=cmd_uninstall(&ctx);}
    else if(strcmp(command,"recover")==0){if(!mutating){struct transaction t;int tr=load_transaction(&ctx,&t);if(tr==0){printf("Recovery plan: restore the verified pre-transaction snapshot for %s (phase %s).\n",t.action,t.phase);result=0;}else if(tr<0)result=bad("transaction journal is unsafe or corrupt; preserve it for review");else{puts("Recovery plan: no transaction journal is present; no changes.");result=0;}}else{struct transaction t;int tr;if(acquire_lock(&ctx)!=0)result=4;else{int active=active_plist_present(&ctx),metadata=service_lifecycle_metadata_present(&ctx);if(active<0||metadata<0)result=bad("service lifecycle ownership state cannot be inspected safely");else if(active||metadata)result=bad("stop and unregister the project service before package recovery");else{tr=load_transaction(&ctx,&t);if(tr==0)result=recover_transaction(&ctx,&t);else if(tr<0)result=bad("transaction journal is unsafe or corrupt; preserve it for review");else if(clean_all_staging(&ctx)!=0)result=bad("orphan staging entries could not be safely cleaned");else if(remove_empty_uninstalled_data(&ctx)!=0)result=bad("orphan staging was cleaned, but remaining project data was preserved for review");else{puts("No transaction journal is present; orphan staging was safely cleaned.");result=0;}}}}}
    close_context(&ctx);return result;
}
