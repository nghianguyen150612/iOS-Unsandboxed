#if defined(__APPLE__)
#define _DARWIN_C_SOURCE 1
#endif
#define _POSIX_C_SOURCE 200809L
#define _FILE_OFFSET_BITS 64

#include "iu_amethyst_adapter.h"
#include "iu_preflight.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#if defined(__APPLE__)
#define IU_STAT_MTIME_NS(st) ((st).st_mtimespec.tv_nsec)
#define IU_STAT_CTIME_NS(st) ((st).st_ctimespec.tv_nsec)
#else
#define IU_STAT_MTIME_NS(st) ((st).st_mtim.tv_nsec)
#define IU_STAT_CTIME_NS(st) ((st).st_ctim.tv_nsec)
#endif

#define IU_AME_MACH_HEADER_64_SIZE 32U
#define IU_AME_LC_CODE_SIGNATURE UINT32_C(0x1d)
#define IU_AME_CPU_TYPE_ARM64 UINT32_C(0x0100000c)
#define IU_AME_CSMAGIC_EMBEDDED_SIGNATURE UINT32_C(0xfade0cc0)
#define IU_AME_CSMAGIC_CODEDIRECTORY UINT32_C(0xfade0c02)
#define IU_AME_CS_ADHOC UINT32_C(0x2)

_Static_assert(sizeof(struct iu_ame_text_v1) == IU_AME_TEXT_V1_SIZE, "Amethyst text ABI size changed");
_Static_assert(sizeof(struct iu_ame_component_evidence_v1) == IU_AME_COMPONENT_EVIDENCE_V1_SIZE, "Amethyst component ABI size changed");
_Static_assert(sizeof(struct iu_ame_probe_result_v1) == IU_AME_PROBE_RESULT_V1_SIZE, "Amethyst probe ABI size changed");
_Static_assert(sizeof(struct iu_ame_observed_facts_v1) == IU_AME_OBSERVED_FACTS_V1_SIZE, "Amethyst facts ABI size changed");
_Static_assert(sizeof(struct iu_ame_capability_result_v1) == IU_AME_CAPABILITY_RESULT_V1_SIZE, "Amethyst classification ABI size changed");
_Static_assert(sizeof(struct iu_ame_preview_request_v1) == IU_AME_PREVIEW_REQUEST_V1_SIZE, "Amethyst preview request ABI size changed");
_Static_assert(sizeof(struct iu_ame_preview_result_v1) == IU_AME_PREVIEW_RESULT_V1_SIZE, "Amethyst preview ABI size changed");
_Static_assert(sizeof(struct iu_ame_macho_result_v1) == IU_AME_MACHO_RESULT_V1_SIZE, "Amethyst Mach-O ABI size changed");
_Static_assert(sizeof(struct iu_ame_capability_record_v1) == IU_AME_CAPABILITY_RECORD_V1_SIZE, "Amethyst capability record size changed");
_Static_assert(sizeof(struct iu_ame_capability_set_v1) == IU_AME_CAPABILITY_SET_V1_SIZE, "Amethyst capability set size changed");

static uid_t expected_component_uid(void)
{
#ifdef IU_AME_TESTING
    return geteuid();
#else
    return 0;
#endif
}

static gid_t expected_component_gid(void)
{
#ifdef IU_AME_TESTING
    return getegid();
#else
    return 0;
#endif
}

/* Small standalone SHA-256 implementation to avoid an OpenSSL/runtime link. */
struct sha256_ctx { uint32_t h[8]; uint64_t bits; uint8_t block[64]; size_t used; };
static const uint32_t sha_k[64] = {
  0x428a2f98U,0x71374491U,0xb5c0fbcfU,0xe9b5dba5U,0x3956c25bU,0x59f111f1U,0x923f82a4U,0xab1c5ed5U,
  0xd807aa98U,0x12835b01U,0x243185beU,0x550c7dc3U,0x72be5d74U,0x80deb1feU,0x9bdc06a7U,0xc19bf174U,
  0xe49b69c1U,0xefbe4786U,0x0fc19dc6U,0x240ca1ccU,0x2de92c6fU,0x4a7484aaU,0x5cb0a9dcU,0x76f988daU,
  0x983e5152U,0xa831c66dU,0xb00327c8U,0xbf597fc7U,0xc6e00bf3U,0xd5a79147U,0x06ca6351U,0x14292967U,
  0x27b70a85U,0x2e1b2138U,0x4d2c6dfcU,0x53380d13U,0x650a7354U,0x766a0abbU,0x81c2c92eU,0x92722c85U,
  0xa2bfe8a1U,0xa81a664bU,0xc24b8b70U,0xc76c51a3U,0xd192e819U,0xd6990624U,0xf40e3585U,0x106aa070U,
  0x19a4c116U,0x1e376c08U,0x2748774cU,0x34b0bcb5U,0x391c0cb3U,0x4ed8aa4aU,0x5b9cca4fU,0x682e6ff3U,
  0x748f82eeU,0x78a5636fU,0x84c87814U,0x8cc70208U,0x90befffaU,0xa4506cebU,0xbef9a3f7U,0xc67178f2U
};
static uint32_t rotr(uint32_t x, unsigned n) { return (x >> n) | (x << (32U - n)); }
static void sha_transform(struct sha256_ctx *c, const uint8_t *p)
{
    uint32_t w[64], a,b,d,e,f,g,h,t1,t2,cc; size_t i;
    for (i=0;i<16;i++) w[i]=((uint32_t)p[i*4]<<24)|((uint32_t)p[i*4+1]<<16)|((uint32_t)p[i*4+2]<<8)|p[i*4+3];
    for (i=16;i<64;i++) { uint32_t s0=rotr(w[i-15],7)^rotr(w[i-15],18)^(w[i-15]>>3); uint32_t s1=rotr(w[i-2],17)^rotr(w[i-2],19)^(w[i-2]>>10); w[i]=w[i-16]+s0+w[i-7]+s1; }
    a=c->h[0]; b=c->h[1]; cc=c->h[2]; d=c->h[3]; e=c->h[4]; f=c->h[5]; g=c->h[6]; h=c->h[7];
    for(i=0;i<64;i++){uint32_t s1=rotr(e,6)^rotr(e,11)^rotr(e,25), ch=(e&f)^(~e&g); t1=h+s1+ch+sha_k[i]+w[i]; uint32_t s0=rotr(a,2)^rotr(a,13)^rotr(a,22), maj=(a&b)^(a&cc)^(b&cc); t2=s0+maj; h=g;g=f;f=e;e=d+t1;d=cc;cc=b;b=a;a=t1+t2;}
    c->h[0]+=a;c->h[1]+=b;c->h[2]+=cc;c->h[3]+=d;c->h[4]+=e;c->h[5]+=f;c->h[6]+=g;c->h[7]+=h;
}
static void sha_init(struct sha256_ctx *c){static const uint32_t iv[8]={0x6a09e667U,0xbb67ae85U,0x3c6ef372U,0xa54ff53aU,0x510e527fU,0x9b05688cU,0x1f83d9abU,0x5be0cd19U};memcpy(c->h,iv,sizeof(iv));c->bits=0;c->used=0;}
static void sha_update(struct sha256_ctx *c,const uint8_t *p,size_t n){c->bits+=(uint64_t)n*8U;while(n){size_t take=64-c->used;if(take>n)take=n;memcpy(c->block+c->used,p,take);c->used+=take;p+=take;n-=take;if(c->used==64){sha_transform(c,c->block);c->used=0;}}}
static void sha_final(struct sha256_ctx *c,uint8_t out[32]){uint64_t bits=c->bits;size_t i;c->block[c->used++]=0x80;if(c->used>56){while(c->used<64)c->block[c->used++]=0;sha_transform(c,c->block);c->used=0;}while(c->used<56)c->block[c->used++]=0;for(i=0;i<8;i++)c->block[63-i]=(uint8_t)(bits>>(i*8));sha_transform(c,c->block);for(i=0;i<8;i++){out[i*4]=(uint8_t)(c->h[i]>>24);out[i*4+1]=(uint8_t)(c->h[i]>>16);out[i*4+2]=(uint8_t)(c->h[i]>>8);out[i*4+3]=(uint8_t)c->h[i];}}

static uint32_t rd32le(const uint8_t *p){return (uint32_t)p[0]|((uint32_t)p[1]<<8)|((uint32_t)p[2]<<16)|((uint32_t)p[3]<<24);}
static uint32_t rd32be(const uint8_t *p){return ((uint32_t)p[0]<<24)|((uint32_t)p[1]<<16)|((uint32_t)p[2]<<8)|(uint32_t)p[3];}
static int text_valid(const struct iu_ame_text_v1 *t){return t!=NULL&&t->length<IU_AME_TEXT_CAPACITY&&t->value[t->length]=='\0'&&memchr(t->value,'\0',t->length)==NULL;}
static void set_text(struct iu_ame_text_v1 *t,const char *s){size_t n=strlen(s);if(n>=sizeof(t->value))n=sizeof(t->value)-1;memset(t,0,sizeof(*t));memcpy(t->value,s,n);t->length=(uint32_t)n;}
static void set_probe(struct iu_ame_probe_result_v1 *r,uint32_t error,uint32_t compat){memset(r,0,sizeof(*r));r->abi_version=IU_AME_ADAPTER_ABI_VERSION;r->struct_size=(uint32_t)sizeof(*r);r->error_code=error;r->compatibility=compat;r->component_count=IU_AME_COMPONENT_COUNT;r->build_evidence=IU_AME_BUILD_UNKNOWN;r->launchd_hook_evidence=IU_AME_HOOK_UNKNOWN;r->base_hook_evidence=IU_AME_HOOK_UNKNOWN;set_text(&r->source_revision,IU_AME_SOURCE_REVISION);}
static uint32_t result_file_type(mode_t mode){if(S_ISREG(mode))return IU_AME_FILE_REGULAR;if(S_ISLNK(mode))return IU_AME_FILE_SYMLINK;return IU_AME_FILE_OTHER;}

static int walk_parent(const char *path,char copy[4096],int *parent_fd,char **leaf)
{
    size_t length,index;char *cursor;int fd,next;
    if (path == NULL) return -1;
    length=strnlen(path,4096);if(length<2||length>=4096||path[0]!='/')return -1;
    memcpy(copy,path,length+1);fd=open("/",O_RDONLY|O_DIRECTORY|O_CLOEXEC);if(fd<0)return -1;cursor=copy+1;
    for(index=1;index<length;index++){
        if(cursor[index-1]=='/'&&cursor[index]=='/'){close(fd);errno=EINVAL;return -1;}
    }
    if(copy[length-1]=='/'){close(fd);errno=EINVAL;return -1;}
    for(;;){char *slash=strchr(cursor,'/');size_t part=slash?(size_t)(slash-cursor):strlen(cursor);
        if(part==0||(part==1&&cursor[0]=='.')||(part==2&&cursor[0]=='.'&&cursor[1]=='.')){close(fd);errno=EINVAL;return -1;}
        if(slash==NULL){*parent_fd=fd;*leaf=cursor;return 0;}
        *slash='\0';next=openat(fd,cursor,O_RDONLY|O_DIRECTORY|O_CLOEXEC
#ifdef O_NOFOLLOW
                                |O_NOFOLLOW
#endif
        );close(fd);if(next<0)return -1;fd=next;cursor=slash+1;
    }
}

static int safe_lstat(const char *path,struct stat *st)
{
    char copy[4096],*leaf;int parent=-1,rc;
    if(walk_parent(path,copy,&parent,&leaf)!=0)return -1;
    rc=fstatat(parent,leaf,st,AT_SYMLINK_NOFOLLOW);close(parent);return rc;
}

static int code_directory_is_parseable(const uint8_t *blob,uint32_t length,uint32_t *flags)
{
    uint32_t hash_offset,ident_offset,special_slots,code_slots,hash_size;uint64_t hash_bytes,special_bytes;
    if(length<44U)return 0;
    *flags=rd32be(blob+12U);hash_offset=rd32be(blob+16U);ident_offset=rd32be(blob+20U);special_slots=rd32be(blob+24U);code_slots=rd32be(blob+28U);hash_size=blob[36U];
    if(hash_size==0||code_slots==0||hash_offset>length)return 0;
    hash_bytes=(uint64_t)code_slots*(uint64_t)hash_size;special_bytes=(uint64_t)special_slots*(uint64_t)hash_size;
    if(special_bytes>(uint64_t)hash_offset||hash_bytes>(uint64_t)length-(uint64_t)hash_offset)return 0;
    if(ident_offset==0||ident_offset>=length||memchr(blob+ident_offset,'\0',length-ident_offset)==NULL)return 0;
    return 1;
}

static int read_bounded_regular(const char *path,uint64_t max_size,uint8_t **bytes,struct stat *before,struct stat *after)
{
    struct stat lst;int fd=-1,parent=-1;char copy[4096],*leaf;uint8_t *data=NULL;size_t done=0;int status=-1;
    if(safe_lstat(path,&lst)!=0) return -1;
    if(!S_ISREG(lst.st_mode)||lst.st_nlink!=1||lst.st_size<0||(uint64_t)lst.st_size>max_size){errno=EFBIG;return -2;}
    if(walk_parent(path,copy,&parent,&leaf)!=0)return -1;
    fd=openat(parent,leaf,O_RDONLY|O_CLOEXEC|O_NONBLOCK
#ifdef O_NOFOLLOW
            |O_NOFOLLOW
#endif
    );
    close(parent);
    if(fd<0)return -1;
    if(fstat(fd,before)!=0||!S_ISREG(before->st_mode)||before->st_nlink!=1||before->st_dev!=lst.st_dev||before->st_ino!=lst.st_ino||before->st_size!=lst.st_size||before->st_uid!=lst.st_uid||before->st_gid!=lst.st_gid||before->st_mode!=lst.st_mode||before->st_mtime!=lst.st_mtime||IU_STAT_MTIME_NS(*before)!=IU_STAT_MTIME_NS(lst)||before->st_ctime!=lst.st_ctime||IU_STAT_CTIME_NS(*before)!=IU_STAT_CTIME_NS(lst)){errno=EAGAIN;goto done;}
    data=malloc((size_t)before->st_size==0?1U:(size_t)before->st_size);if(data==NULL)goto done;
    while(done<(size_t)before->st_size){ssize_t n=read(fd,data+done,(size_t)before->st_size-done);if(n<0&&errno==EINTR)continue;if(n<=0){errno=EIO;goto done;}done+=(size_t)n;}
    if(fstat(fd,after)!=0||after->st_dev!=before->st_dev||after->st_ino!=before->st_ino||after->st_size!=before->st_size||after->st_uid!=before->st_uid||after->st_gid!=before->st_gid||after->st_mode!=before->st_mode||after->st_nlink!=before->st_nlink||after->st_mtime!=before->st_mtime||IU_STAT_MTIME_NS(*after)!=IU_STAT_MTIME_NS(*before)||after->st_ctime!=before->st_ctime||IU_STAT_CTIME_NS(*after)!=IU_STAT_CTIME_NS(*before)){errno=EAGAIN;goto done;}
    *bytes=data;data=NULL;status=0;
done:free(data);close(fd);return status;
}

static uint32_t classify_macho_bytes(const uint8_t *p,size_t n,uint32_t *arch)
{
    uint32_t magic,cpu,ncmds,cmdbytes,cs_off=0,cs_size=0;uint32_t i;size_t pos,commands_end;int found=0;
    *arch=IU_ARCH_UNKNOWN;
    if(n<4)return IU_AME_MACHO_TRUNCATED_OR_CORRUPT;
    magic=rd32le(p);
    if(magic!=UINT32_C(0xfeedfacf)){
        if(magic==UINT32_C(0xfeedface)||magic==UINT32_C(0xcefaedfe)||magic==UINT32_C(0xcffaedfe)||magic==UINT32_C(0xcafebabe)||magic==UINT32_C(0xbebafeca))return IU_AME_MACHO_UNSUPPORTED_FORMAT;
        return IU_AME_MACHO_UNSUPPORTED_FORMAT;
    }
    if(n<IU_AME_MACH_HEADER_64_SIZE)return IU_AME_MACHO_TRUNCATED_OR_CORRUPT;
    cpu=rd32le(p+4);*arch=cpu==IU_AME_CPU_TYPE_ARM64?IU_ARCH_ARM64:IU_ARCH_UNKNOWN;
    if(cpu!=IU_AME_CPU_TYPE_ARM64)return IU_AME_MACHO_UNSUPPORTED_FORMAT;
    ncmds=rd32le(p+16);cmdbytes=rd32le(p+20);
    if(cmdbytes>n-IU_AME_MACH_HEADER_64_SIZE||ncmds>cmdbytes/8U)return IU_AME_MACHO_TRUNCATED_OR_CORRUPT;
    pos=IU_AME_MACH_HEADER_64_SIZE;commands_end=pos+(size_t)cmdbytes;
    for(i=0;i<ncmds;i++){
        uint32_t cmd,cmdsize;
        if(pos>commands_end||commands_end-pos<8U)return IU_AME_MACHO_TRUNCATED_OR_CORRUPT;
        cmd=rd32le(p+pos);cmdsize=rd32le(p+pos+4);
        if(cmdsize<8U||(cmdsize&UINT32_C(3))!=0||cmdsize>commands_end-pos)return IU_AME_MACHO_TRUNCATED_OR_CORRUPT;
        if(cmd==IU_AME_LC_CODE_SIGNATURE){if(found||cmdsize!=16U)return IU_AME_MACHO_TRUNCATED_OR_CORRUPT;found=1;cs_off=rd32le(p+pos+8);cs_size=rd32le(p+pos+12);}
        pos+=cmdsize;
    }
    if(pos!=commands_end)return IU_AME_MACHO_TRUNCATED_OR_CORRUPT;
    if(!found)return IU_AME_MACHO_NO_CODE_SIGNATURE;
    if(cs_size==0)return IU_AME_MACHO_EMPTY_SIGNATURE;
    if((uint64_t)cs_off>n||(uint64_t)cs_size>(uint64_t)n-(uint64_t)cs_off)return IU_AME_MACHO_EMPTY_SIGNATURE;
    {
        const uint8_t *b=p+cs_off;uint32_t bmagic,blen,count,j;int found_cd=0,adhoc=0;
        if(cs_size<12U)return IU_AME_MACHO_MALFORMED_SIGNATURE;
        bmagic=rd32be(b);blen=rd32be(b+4);count=rd32be(b+8);
        if(bmagic!=IU_AME_CSMAGIC_EMBEDDED_SIGNATURE||blen<12U||blen>cs_size||count>(blen-12U)/8U)return IU_AME_MACHO_MALFORMED_SIGNATURE;
        for(j=0;j<count;j++){
            uint32_t off=rd32be(b+16U+(size_t)j*8U);uint32_t smagic,slen;
            if(off>blen||blen-off<8U)return IU_AME_MACHO_MALFORMED_SIGNATURE;
            smagic=rd32be(b+off);slen=rd32be(b+off+4U);
            if(slen<8U||slen>blen-off)return IU_AME_MACHO_MALFORMED_SIGNATURE;
            if(smagic==IU_AME_CSMAGIC_CODEDIRECTORY){uint32_t flags;if(!code_directory_is_parseable(b+off,slen,&flags))return IU_AME_MACHO_MALFORMED_SIGNATURE;found_cd=1;if((flags&IU_AME_CS_ADHOC)!=0)adhoc=1;}
        }
        if(!found_cd)return IU_AME_MACHO_MALFORMED_SIGNATURE;
        return adhoc?IU_AME_MACHO_ADHOC_SIGNATURE:IU_AME_MACHO_PARSEABLE_CODEDIRECTORY;
    }
}

int32_t iu_ame_macho_inspect_v1(const char *path,struct iu_ame_macho_result_v1 *r)
{
    uint8_t *bytes=NULL;struct stat before,after;int rc;uint32_t arch=IU_ARCH_UNKNOWN;
    if (r == NULL) return -1;
    memset(r,0,sizeof(*r));r->abi_version=IU_AME_ADAPTER_ABI_VERSION;r->struct_size=(uint32_t)sizeof(*r);r->state=IU_AME_MACHO_IO_ERROR;
    rc=read_bounded_regular(path,IU_AME_MAX_FILE_SIZE,&bytes,&before,&after);
    if(rc!=0){r->error_code=rc==-2?IU_AME_ERROR_UNSAFE_COMPONENT:IU_AME_ERROR_IO;return -1;}
    r->state=classify_macho_bytes(bytes,(size_t)before.st_size,&arch);r->architecture=arch;
    if(arch==IU_ARCH_ARM64){r->macho_cputype=rd32le(bytes+4);r->macho_cpusubtype=rd32le(bytes+8);r->macho_filetype=rd32le(bytes+12);}
    r->file_type=IU_AME_FILE_REGULAR;r->owner_uid=(uint32_t)before.st_uid;r->owner_gid=(uint32_t)before.st_gid;r->mode=(uint32_t)(before.st_mode&07777);r->link_count=(uint32_t)before.st_nlink;r->device=(uint64_t)before.st_dev;r->inode=(uint64_t)before.st_ino;r->file_size=(uint64_t)before.st_size;
    free(bytes);return 0;
}

static int same_inspection_stat(const struct stat *a, const struct stat *b)
{
    return a->st_dev == b->st_dev && a->st_ino == b->st_ino &&
           a->st_mode == b->st_mode && a->st_uid == b->st_uid &&
           a->st_gid == b->st_gid && a->st_nlink == b->st_nlink &&
           a->st_size == b->st_size && a->st_mtime == b->st_mtime &&
           IU_STAT_MTIME_NS(*a) == IU_STAT_MTIME_NS(*b) &&
           a->st_ctime == b->st_ctime && IU_STAT_CTIME_NS(*a) == IU_STAT_CTIME_NS(*b);
}

int32_t iu_ame_macho_inspect_fd_v1(int fd, struct iu_ame_macho_result_v1 *r)
{
    struct stat before, after;
    uint8_t *bytes = NULL;
    size_t done = 0;
    uint32_t arch = IU_ARCH_UNKNOWN;
    if (r == NULL) return -IU_AME_ERROR_INVALID_ARGUMENT;
    memset(r, 0, sizeof(*r));
    r->abi_version = IU_AME_ADAPTER_ABI_VERSION;
    r->struct_size = (uint32_t)sizeof(*r);
    r->state = IU_AME_MACHO_IO_ERROR;
    if (fd < 0 || fstat(fd, &before) != 0 || !S_ISREG(before.st_mode) ||
        before.st_nlink != 1 || before.st_size < 0 ||
        (uint64_t)before.st_size > IU_AME_MAX_FILE_SIZE) {
        r->error_code = IU_AME_ERROR_UNSAFE_COMPONENT;
        return -IU_AME_ERROR_IO;
    }
    bytes = malloc(before.st_size == 0 ? 1U : (size_t)before.st_size);
    if (bytes == NULL) { r->error_code = IU_AME_ERROR_INTERNAL; return -IU_AME_ERROR_IO; }
    while (done < (size_t)before.st_size) {
        ssize_t got = pread(fd, bytes + done, (size_t)before.st_size - done, (off_t)done);
        if (got < 0 && errno == EINTR) continue;
        if (got <= 0) { free(bytes); r->error_code = IU_AME_ERROR_IO; return -IU_AME_ERROR_IO; }
        done += (size_t)got;
    }
    if (fstat(fd, &after) != 0 || !same_inspection_stat(&before, &after)) {
        free(bytes); r->error_code = IU_AME_ERROR_IDENTITY_MISMATCH; return -IU_AME_ERROR_IDENTITY_MISMATCH;
    }
    r->state = classify_macho_bytes(bytes, (size_t)before.st_size, &arch);
    r->architecture = arch;
    if (arch == IU_ARCH_ARM64 && before.st_size >= 16) {
        r->macho_cputype = rd32le(bytes + 4);
        r->macho_cpusubtype = rd32le(bytes + 8);
        r->macho_filetype = rd32le(bytes + 12);
    }
    r->file_type = IU_AME_FILE_REGULAR;
    r->owner_uid = (uint32_t)before.st_uid; r->owner_gid = (uint32_t)before.st_gid;
    r->mode = (uint32_t)(before.st_mode & 07777); r->link_count = (uint32_t)before.st_nlink;
    r->device = (uint64_t)before.st_dev; r->inode = (uint64_t)before.st_ino;
    r->file_size = (uint64_t)before.st_size;
    free(bytes);
    return 0;
}

int32_t iu_ame_sha256_fd_v1(int fd, uint8_t digest[IU_AME_SHA256_SIZE])
{
    struct stat before, after;
    struct sha256_ctx hash;
    uint8_t buffer[16384];
    off_t offset = 0;
    if (fd < 0 || digest == NULL || fstat(fd, &before) != 0 ||
        !S_ISREG(before.st_mode) || before.st_nlink != 1 || before.st_size < 0 ||
        (uint64_t)before.st_size > IU_AME_MAX_FILE_SIZE) return -IU_AME_ERROR_UNSAFE_COMPONENT;
    sha_init(&hash);
    while (offset < before.st_size) {
        size_t want = (size_t)(before.st_size - offset);
        ssize_t got;
        if (want > sizeof(buffer)) want = sizeof(buffer);
        got = pread(fd, buffer, want, offset);
        if (got < 0 && errno == EINTR) continue;
        if (got <= 0) return -IU_AME_ERROR_IO;
        sha_update(&hash, buffer, (size_t)got);
        offset += got;
    }
    if (fstat(fd, &after) != 0 || !same_inspection_stat(&before, &after))
        return -IU_AME_ERROR_IDENTITY_MISMATCH;
    sha_final(&hash, digest);
    return 0;
}

int32_t iu_ame_collect_component_v1(uint32_t id,const char *path,struct iu_ame_component_evidence_v1 *r)
{
    struct stat lst,before,after;uint8_t *bytes=NULL;struct sha256_ctx hash;int rc;uint32_t architecture;
    if (r == NULL) return -1;
    memset(r,0,sizeof(*r));r->struct_size=(uint32_t)sizeof(*r);r->component_id=id;r->file_type=IU_AME_FILE_MISSING;
    if(id>=IU_AME_COMPONENT_COUNT||path==NULL||strnlen(path,4096)>=4096)return -1;
    if(safe_lstat(path,&lst)!=0){if(errno==ENOENT)return 0;r->file_type=IU_AME_FILE_UNREADABLE;return -1;}
    r->file_type=result_file_type(lst.st_mode);r->owner_uid=(uint32_t)lst.st_uid;r->owner_gid=(uint32_t)lst.st_gid;r->mode=(uint32_t)(lst.st_mode&07777);r->link_count=(uint32_t)lst.st_nlink;r->device=(uint64_t)lst.st_dev;r->inode=(uint64_t)lst.st_ino;r->file_size=lst.st_size<0?0:(uint64_t)lst.st_size;
    if(r->file_type!=IU_AME_FILE_REGULAR)return -1;
    if(lst.st_nlink!=1||lst.st_uid!=expected_component_uid()||lst.st_gid!=expected_component_gid()||(lst.st_mode&(S_IWGRP|S_IWOTH|S_ISUID|S_ISGID))!=0||lst.st_size<0||(uint64_t)lst.st_size>IU_AME_MAX_FILE_SIZE){r->file_type=IU_AME_FILE_UNSAFE;return -1;}
    rc=read_bounded_regular(path,IU_AME_MAX_FILE_SIZE,&bytes,&before,&after);if(rc!=0){r->file_type=rc==-2?IU_AME_FILE_UNSAFE:IU_AME_FILE_UNREADABLE;return -1;}
    if(before.st_uid!=expected_component_uid()||before.st_gid!=expected_component_gid()||(before.st_mode&(S_IWGRP|S_IWOTH|S_ISUID|S_ISGID))!=0){free(bytes);r->file_type=IU_AME_FILE_UNSAFE;return -1;}
    sha_init(&hash);sha_update(&hash,bytes,(size_t)before.st_size);sha_final(&hash,r->sha256);r->sha256_valid=1;
    r->evidence_flags=IU_AME_EVIDENCE_COMPLETE_READ; /* complete read and stable descriptor identity */
    r->file_size=(uint64_t)before.st_size;r->device=(uint64_t)before.st_dev;r->inode=(uint64_t)before.st_ino;
    r->macho_identity=classify_macho_bytes(bytes,(size_t)before.st_size,&architecture);
    if(architecture==IU_ARCH_ARM64){r->macho_cputype=rd32le(bytes+4);r->macho_cpusubtype=rd32le(bytes+8);r->macho_filetype=rd32le(bytes+12);}
    free(bytes);
    return 0;
}

int32_t iu_ame_component_evidence_recheck_v1(const struct iu_ame_component_evidence_v1 *e,const char *path)
{
    struct iu_ame_component_evidence_v1 current;
    if(e==NULL||path==NULL)return -IU_AME_ERROR_INVALID_ARGUMENT;
    if(e->struct_size!=sizeof(*e))return -IU_AME_ERROR_ABI_MISMATCH;
    if(e->component_id>=IU_AME_COMPONENT_COUNT||e->file_type!=IU_AME_FILE_REGULAR||e->evidence_flags!=IU_AME_EVIDENCE_COMPLETE_READ||e->sha256_valid!=1||e->link_count!=1||e->file_size>IU_AME_MAX_FILE_SIZE)return -IU_AME_ERROR_INVALID_ARGUMENT;
    if(iu_ame_collect_component_v1(e->component_id,path,&current)!=0)return -IU_AME_ERROR_IO;
    if(current.file_type!=e->file_type||current.owner_uid!=e->owner_uid||current.owner_gid!=e->owner_gid||current.mode!=e->mode||current.link_count!=e->link_count||current.device!=e->device||current.inode!=e->inode||current.file_size!=e->file_size||current.macho_identity!=e->macho_identity||current.macho_cputype!=e->macho_cputype||current.macho_cpusubtype!=e->macho_cpusubtype||current.macho_filetype!=e->macho_filetype||current.sha256_valid!=e->sha256_valid||memcmp(current.sha256,e->sha256,IU_AME_SHA256_SIZE)!=0)return -IU_AME_ERROR_IDENTITY_MISMATCH;
    return 0;
}

static uint32_t classify_facts(const struct iu_ame_observed_facts_v1 *f)
{
    if(f->system_family!=IU_SYSTEM_IOS||f->architecture!=IU_ARCH_ARM64||f->reference_device_match==IU_MATCH_NO)return IU_AME_UNSUPPORTED_PLATFORM;
    if(f->reference_os_match==IU_MATCH_NO)return IU_AME_VERSION_MISMATCH;
    if(f->build_evidence==IU_AME_BUILD_VERSION_MISMATCH)return IU_AME_VERSION_MISMATCH;
    if((f->component_present_mask&UINT32_C(3))!=UINT32_C(3)||(f->component_safe_mask&UINT32_C(3))!=UINT32_C(3))return IU_AME_COMPONENT_MISSING;
#ifdef IU_AME_TESTING
    if(f->reference_device_match==IU_MATCH_YES&&f->reference_os_match==IU_MATCH_YES&&f->device_evidence_complete==1&&f->build_evidence==IU_AME_BUILD_TRUSTED_HASH_MATCH&&f->launchd_hook_evidence==IU_AME_HOOK_INDEPENDENTLY_VERIFIED&&f->base_hook_evidence==IU_AME_HOOK_INDEPENDENTLY_VERIFIED&&f->source_revision.length==40&&memcmp(f->source_revision.value,IU_AME_SOURCE_REVISION,40)==0)return IU_AME_SUPPORTED_AND_VERIFIED;
#endif
    if(f->source_revision.length==40&&memcmp(f->source_revision.value,IU_AME_SOURCE_REVISION,40)==0)return IU_AME_SOURCE_REVISION_KNOWN;
    if(f->build_evidence==IU_AME_BUILD_UNKNOWN)return IU_AME_INSTALLED_BUILD_UNVERIFIED;
    if(f->launchd_hook_evidence!=IU_AME_HOOK_INDEPENDENTLY_VERIFIED||f->base_hook_evidence!=IU_AME_HOOK_INDEPENDENTLY_VERIFIED)return IU_AME_HOOK_STATE_UNVERIFIED;
    return IU_AME_INSTALLED_BUILD_UNVERIFIED;
}

int32_t iu_ame_adapter_classify_v1(const struct iu_ame_observed_facts_v1 *f,struct iu_ame_capability_result_v1 *r)
{
    if (r == NULL) return -1;
    memset(r,0,sizeof(*r));r->abi_version=IU_AME_ADAPTER_ABI_VERSION;r->struct_size=(uint32_t)sizeof(*r);r->compatibility=IU_AME_INTERNAL_ERROR;r->error_code=IU_AME_ERROR_INVALID_ARGUMENT;
    if(f==NULL)return -1;
    if(f->abi_version!=IU_AME_ADAPTER_ABI_VERSION||f->struct_size!=sizeof(*f)){r->compatibility=IU_AME_ABI_INCOMPATIBLE;r->error_code=IU_AME_ERROR_ABI_MISMATCH;return -1;}
    if(f->system_family>IU_SYSTEM_WINDOWS||f->architecture>IU_ARCH_X86||f->reference_device_match>IU_MATCH_NO||f->reference_os_match>IU_MATCH_NO||f->build_evidence>IU_AME_BUILD_VERSION_MISMATCH||f->launchd_hook_evidence>IU_AME_HOOK_INDEPENDENTLY_VERIFIED||f->base_hook_evidence>IU_AME_HOOK_INDEPENDENTLY_VERIFIED||f->device_evidence_complete>1||f->component_present_mask&~UINT32_C(3)||f->component_safe_mask&~UINT32_C(3)||!text_valid(&f->device_identifier)||!text_valid(&f->product_version)||!text_valid(&f->source_revision)){
        r->error_code=IU_AME_ERROR_INVALID_ENUM;return -1;
    }
    r->compatibility=classify_facts(f);r->error_code=IU_AME_ERROR_NONE;return 0;
}

static uint32_t capability_status(uint32_t id)
{
    struct iu_ame_capability_set_v1 s;size_t i;if(iu_ame_capabilities_v1(&s)!=0)return IU_AME_CAP_BLOCKED;for(i=0;i<s.record_count;i++)if(s.records[i].capability_id==id)return s.records[i].status;return 0;
}

int32_t iu_ame_adapter_preview_v1(const struct iu_ame_preview_request_v1 *q,struct iu_ame_preview_result_v1 *r)
{
    struct iu_ame_probe_result_v1 probe;struct iu_policy_result_v1 policy;uint32_t cap;
    if (r == NULL) return -1;
    memset(r,0,sizeof(*r));r->abi_version=IU_AME_ADAPTER_ABI_VERSION;r->struct_size=(uint32_t)sizeof(*r);r->preview_decision=IU_AME_PREVIEW_BLOCKED;r->adapter_compatibility=IU_AME_INTERNAL_ERROR;r->policy_outcome=IU_POLICY_DENY_INTERNAL_ERROR;
    if(q==NULL){r->blocking_reason=IU_AME_ERROR_INVALID_ARGUMENT;return -1;}
    if(q->abi_version!=IU_AME_ADAPTER_ABI_VERSION||q->struct_size!=sizeof(*q)){r->adapter_compatibility=IU_AME_ABI_INCOMPATIBLE;r->blocking_reason=IU_AME_PREVIEW_REASON_INVALID_INPUT;return -1;}
    if(q->required_capability<IU_AME_CAP_READ_ONLY_PROBE||q->required_capability>IU_AME_CAP_FUTURE_EXECUTION_ADAPTER||q->reserved_operation>IU_AME_OP_VERIFY_LAUNCH_BOUNDARY){r->blocking_reason=IU_AME_PREVIEW_REASON_INVALID_INPUT;return -1;}
    r->required_capability=q->required_capability;cap=capability_status(q->required_capability);r->capability_status=cap;
    if(q->reserved_operation!=0){r->preview_decision=IU_AME_PREVIEW_NOT_IMPLEMENTED;r->blocking_reason=IU_AME_PREVIEW_REASON_RESERVED_OPERATION;return 0;}
    if(iu_policy_evaluate_v1(&q->policy_config,&q->target,&policy)!=0){r->policy_outcome=IU_POLICY_DENY_INTERNAL_ERROR;r->blocking_reason=IU_AME_PREVIEW_REASON_POLICY;return 0;}
    r->policy_outcome=policy.outcome;r->blocking_reason=policy.outcome==IU_POLICY_ALLOW_ELIGIBLE?IU_AME_PREVIEW_REASON_NONE:IU_AME_PREVIEW_REASON_POLICY;
    if(iu_ame_adapter_probe_v1(&probe)!=0){r->adapter_compatibility=IU_AME_INTERNAL_ERROR;return 0;}
    r->adapter_compatibility=probe.compatibility;
    /* P003 is necessary; P009 never turns compatibility evidence into a grant. */
    if(policy.outcome!=IU_POLICY_ALLOW_ELIGIBLE)return 0;
    if(probe.compatibility!=IU_AME_SUPPORTED_AND_VERIFIED){r->blocking_reason=IU_AME_PREVIEW_REASON_ADAPTER_COMPATIBILITY;return 0;}
    if(cap!=IU_AME_CAP_SOURCE_CONFIRMED&&cap!=IU_AME_CAP_RUNTIME_VERIFIED){r->blocking_reason=IU_AME_PREVIEW_REASON_CAPABILITY;return 0;}
    r->preview_decision=IU_AME_PREVIEW_HYPOTHETICALLY_ELIGIBLE;r->blocking_reason=IU_AME_PREVIEW_REASON_NONE;r->operational_authorization=0;return 0;
}

int32_t iu_ame_adapter_reserved_operation_v1(uint32_t operation)
{
    if(operation<IU_AME_OP_PREPARE_EXECUTABLE||operation>IU_AME_OP_VERIFY_LAUNCH_BOUNDARY)return -IU_AME_ERROR_INVALID_ENUM;
    return IU_AME_ERROR_NOT_IMPLEMENTED;
}

int32_t iu_ame_adapter_probe_v1(struct iu_ame_probe_result_v1 *r)
{
    static const char *const paths[IU_AME_COMPONENT_COUNT]={"/amethyst/launchd_hook.dylib","/usr/lib/base_hook.dylib"};
    struct iu_preflight_result_v1 platform;struct iu_ame_observed_facts_v1 facts;struct iu_ame_capability_result_v1 classified;size_t i;uint32_t mask=0;
    if (r == NULL) return -1;
    set_probe(r,IU_AME_ERROR_NONE,IU_AME_INSTALLED_BUILD_UNVERIFIED);
    if(iu_ame_capabilities_v1(&r->capabilities)!=0){set_probe(r,IU_AME_ERROR_INTERNAL,IU_AME_INTERNAL_ERROR);return -1;}
    for(i=0;i<IU_AME_COMPONENT_COUNT;i++){
        (void)iu_ame_collect_component_v1((uint32_t)i,paths[i],&r->components[i]);
        if(r->components[i].file_type==IU_AME_FILE_REGULAR&&r->components[i].sha256_valid==1)mask|=UINT32_C(1)<<i;
    }
    if(iu_preflight_detect_v1(&platform)!=0){r->compatibility=IU_AME_INTERNAL_ERROR;r->error_code=IU_AME_ERROR_INTERNAL;return -1;}
    memset(&facts,0,sizeof(facts));facts.abi_version=IU_AME_ADAPTER_ABI_VERSION;facts.struct_size=(uint32_t)sizeof(facts);facts.system_family=platform.system_family;facts.architecture=platform.architecture;facts.reference_device_match=platform.reference_device_match;facts.reference_os_match=platform.reference_os_match;facts.component_present_mask=mask;facts.component_safe_mask=mask;facts.build_evidence=IU_AME_BUILD_UNKNOWN;facts.launchd_hook_evidence=IU_AME_HOOK_UNKNOWN;facts.base_hook_evidence=IU_AME_HOOK_UNKNOWN;
    if(platform.machine.length<IU_AME_TEXT_CAPACITY){facts.device_identifier.length=platform.machine.length;memcpy(facts.device_identifier.value,platform.machine.value,platform.machine.length+1);}
    if(platform.product_version.length<IU_AME_TEXT_CAPACITY){facts.product_version.length=platform.product_version.length;memcpy(facts.product_version.value,platform.product_version.value,platform.product_version.length+1);}
    if(iu_ame_adapter_classify_v1(&facts,&classified)!=0){r->compatibility=classified.compatibility;r->error_code=classified.error_code;return -1;}
    r->compatibility=classified.compatibility;
    /* A component filename and package version are not hook-state evidence. */
    return 0;
}

const char *iu_ame_compatibility_name_v1(uint32_t c)
{
    switch(c){case IU_AME_SUPPORTED_AND_VERIFIED:return "SUPPORTED_AND_VERIFIED";case IU_AME_SOURCE_REVISION_KNOWN:return "SOURCE_REVISION_KNOWN";case IU_AME_INSTALLED_BUILD_UNVERIFIED:return "INSTALLED_BUILD_UNVERIFIED";case IU_AME_COMPONENT_MISSING:return "COMPONENT_MISSING";case IU_AME_VERSION_MISMATCH:return "VERSION_MISMATCH";case IU_AME_UNSUPPORTED_PLATFORM:return "UNSUPPORTED_PLATFORM";case IU_AME_HOOK_STATE_UNVERIFIED:return "HOOK_STATE_UNVERIFIED";case IU_AME_ABI_INCOMPATIBLE:return "ABI_INCOMPATIBLE";default:return "INTERNAL_ERROR";}
}

const char *iu_ame_macho_state_name_v1(uint32_t s)
{
    switch(s){case IU_AME_MACHO_PARSEABLE_CODEDIRECTORY:return "PARSEABLE_CODEDIRECTORY";case IU_AME_MACHO_ADHOC_SIGNATURE:return "ADHOC_SIGNATURE";case IU_AME_MACHO_MALFORMED_SIGNATURE:return "MALFORMED_SIGNATURE";case IU_AME_MACHO_EMPTY_SIGNATURE:return "EMPTY_OR_UNUSABLE_SIGNATURE";case IU_AME_MACHO_NO_CODE_SIGNATURE:return "NO_LC_CODE_SIGNATURE";case IU_AME_MACHO_UNSUPPORTED_FORMAT:return "UNSUPPORTED_ARCHITECTURE_OR_FORMAT";case IU_AME_MACHO_TRUNCATED_OR_CORRUPT:return "TRUNCATED_OR_CORRUPT";default:return "IO_ERROR";}
}
