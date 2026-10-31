#define _DARWIN_C_SOURCE 1
#define _POSIX_C_SOURCE 200809L
#include "iu_trust_manager.h"
#include "iu_trust_store.h"
#include "iu_trust_transaction.h"
#include "iu_checked_readdir.h"
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#if defined(__APPLE__)
#define NS(s,f) ((s)->st_##f##timespec.tv_nsec)
#else
#define NS(s,f) ((s)->st_##f##tim.tv_nsec)
#endif

enum { ART_TX=1, ART_STAGE=2, ART_STAGE_TMP=4, ART_TX_TMP=8, ART_GENERATION=16, ART_GENERATION_TMP=32 };
enum recovery_state { REC_NONE, REC_PREPARED, REC_COMMITTED, REC_UNKNOWN, REC_CONFLICT };
struct snapshot {
    int dir;
    int store_present;
    int generation_present;
    unsigned artifacts;
    size_t store_length,stage_length,journal_length,generation_length;
    unsigned char store[IU_TRUST_STORE_MAX_BYTES];
    unsigned char stage[IU_TRUST_STORE_MAX_BYTES];
    unsigned char journal[IU_TRUST_TRANSACTION_MAX_BYTES];
    unsigned char generation_bytes[IU_TRUST_GENERATION_MAX_BYTES];
    struct stat store_stat,stage_stat,journal_stat,generation_stat;
    struct iu_trust_store_v1 store_value,stage_value;
    struct iu_trust_transaction_v1 transaction;
    struct iu_trust_generation_v1 generation;
    enum recovery_state state;
};

static int same(const struct stat *a,const struct stat *b) {
    return a->st_dev==b->st_dev&&a->st_ino==b->st_ino&&a->st_mode==b->st_mode&&
      a->st_uid==b->st_uid&&a->st_gid==b->st_gid&&a->st_nlink==b->st_nlink&&
      a->st_size==b->st_size&&a->st_mtime==b->st_mtime&&NS(a,m)==NS(b,m)&&
      a->st_ctime==b->st_ctime&&NS(a,c)==NS(b,c);
}
static int safe_dir(int fd,uid_t uid,gid_t gid) {struct stat s;return fstat(fd,&s)==0&&S_ISDIR(s.st_mode)&&s.st_uid==uid&&s.st_gid==gid&&(s.st_mode&07777)==0700;}
static int syncdir(int fd) {
    int r;do{r=fsync(fd);}while(r<0&&errno==EINTR);
    if(r==0)return 0;
    /* iOS filesystems may reject directory fsync; ordinary errors remain fatal. */
    return (errno==EINVAL||errno==ENOTSUP||errno==EOPNOTSUPP)?0:-1;
}
static int load_named(int dir,const char *name,uid_t uid,gid_t gid,unsigned char *bytes,size_t cap,size_t *n,struct stat *identity) {
    struct stat after,path;int fd;size_t pos=0;ssize_t got;
    fd=openat(dir,name,O_RDONLY|O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC);
    if(fd<0)return errno==ENOENT?1:-1;
    if(fstat(fd,identity)||!S_ISREG(identity->st_mode)||identity->st_uid!=uid||identity->st_gid!=gid||
       (identity->st_mode&07777)!=0600||identity->st_nlink!=1||identity->st_size<0||(uint64_t)identity->st_size>cap){close(fd);return -1;}
    while(pos<cap){got=read(fd,bytes+pos,cap-pos);if(got<0&&errno==EINTR)continue;if(got<0){close(fd);return -1;}if(!got)break;pos+=(size_t)got;}
    if(pos==cap){unsigned char extra;do{got=read(fd,&extra,1);}while(got<0&&errno==EINTR);if(got!=0){close(fd);return -1;}}
    if(fstat(fd,&after)||fstatat(dir,name,&path,AT_SYMLINK_NOFOLLOW)||!same(identity,&after)||!same(identity,&path)||pos!=(size_t)identity->st_size){close(fd);return -1;}
    if(close(fd))return -1;
    *n=pos;return 0;
}
static int write_all(int fd,const unsigned char *bytes,size_t n) {
    size_t pos=0;while(pos<n){ssize_t w=write(fd,bytes+pos,n-pos);if(w<0&&errno==EINTR)continue;if(w<=0)return -1;pos+=(size_t)w;}return 0;
}
static int write_new_file(int dir,const char *name,uid_t uid,gid_t gid,const unsigned char *bytes,size_t n,struct stat *identity) {
    int fd=openat(dir,name,O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0600);int e;
    if(fd<0)return -1;
    if(fchown(fd,uid,gid)||fchmod(fd,0600)||write_all(fd,bytes,n))goto fail;
    {int r;do{r=fsync(fd);}while(r<0&&errno==EINTR);if(r)goto fail;}
    if(fstat(fd,identity)||!S_ISREG(identity->st_mode)||identity->st_uid!=uid||identity->st_gid!=gid||(identity->st_mode&07777)!=0600||identity->st_nlink!=1||identity->st_size!=(off_t)n)goto fail;
    if(close(fd))return -1;
    return 0;
fail:e=errno;close(fd);errno=e;return -1;
}
static int keyfile(const char *path,struct iu_trust_record_v1 *record,const char *publisher) {
    char copy[4096],*part,*save=NULL;unsigned char bytes[66];size_t pos=0;struct stat a,b;int dir,fd=-1;ssize_t n;
    if(!path||strlen(path)>=sizeof(copy)||!publisher||strlen(publisher)>=sizeof(record->publisher))return -1;
    strcpy(copy,path);dir=open(path[0]=='/'?"/":".",O_RDONLY|O_DIRECTORY|O_CLOEXEC);if(dir<0)return -1;
    part=strtok_r(copy,"/",&save);
    while(part){char *next=strtok_r(NULL,"/",&save);if(!strcmp(part,".")||!strcmp(part,"..")){close(dir);return -1;}
        fd=openat(dir,part,O_RDONLY|O_NOFOLLOW|O_CLOEXEC|O_NONBLOCK|(next?O_DIRECTORY:0));close(dir);if(fd<0)return -1;if(!next)break;dir=fd;part=next;}
    if(fd<0){close(dir);return -1;}
    if(fstat(fd,&a)||!S_ISREG(a.st_mode)||a.st_nlink!=1||a.st_size!=65){close(fd);return -1;}
    while(pos<sizeof(bytes)){n=read(fd,bytes+pos,sizeof(bytes)-pos);if(n<0&&errno==EINTR)continue;if(n<0){close(fd);return -1;}if(!n)break;pos+=(size_t)n;}
    if(fstat(fd,&b)||!same(&a,&b)||pos!=65||bytes[64]!='\n'){close(fd);return -1;}close(fd);
    memset(record,0,sizeof(*record));record->state=IU_TRUST_KEY_ACTIVE;strcpy(record->publisher,publisher);
    for(unsigned i=0;i<32;i++){unsigned v=0;for(unsigned j=0;j<2;j++){unsigned char c=bytes[i*2+j];if(c>='0'&&c<='9')v=v*16+c-'0';else if(c>='a'&&c<='f')v=v*16+c-'a'+10;else return -1;}record->public_key[i]=(uint8_t)v;}
    return iu_trust_key_id_v1(record->public_key,record->key_id)||iu_trust_record_validate_v1(record)?-1:0;
}
static int compare(const void *a,const void *b){return strcmp(((const struct iu_trust_record_v1 *)a)->key_id,((const struct iu_trust_record_v1 *)b)->key_id);}
static int scan_artifacts(int dir,unsigned *mask) {
    int copy=openat(dir,".",O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);DIR *stream;struct dirent *e;unsigned found=0;int next;
    if(copy<0)return -1;
    stream=fdopendir(copy);if(!stream){close(copy);return -1;}
    while((next=iu_readdir_checked(stream,&e))>0){if(!strcmp(e->d_name,".")||!strcmp(e->d_name,".."))continue;
        if(!strcmp(e->d_name,"store.v1"))continue;
        if(!strcmp(e->d_name,"transaction.v1")){found|=ART_TX;continue;}
        if(!strcmp(e->d_name,IU_TRUST_TRANSACTION_STAGE_NAME)){found|=ART_STAGE;continue;}
        if(!strcmp(e->d_name,".stage.tmp")){found|=ART_STAGE_TMP;continue;}
        if(!strcmp(e->d_name,".transaction.tmp")){found|=ART_TX_TMP;continue;}
        if(!strcmp(e->d_name,"generation.v1")){found|=ART_GENERATION;continue;}
        if(!strcmp(e->d_name,".generation.tmp")){found|=ART_GENERATION_TMP;continue;}
        printf("Foreign trust metadata preserved: %s\n",e->d_name);closedir(stream);return -1;
    }
    if(next<0){closedir(stream);return -1;}
    if(closedir(stream)!=0)return -1;
    *mask=found;return 0;
}
static int read_current(struct snapshot *s,uid_t uid,gid_t gid) {
    int r=load_named(s->dir,"store.v1",uid,gid,s->store,sizeof(s->store),&s->store_length,&s->store_stat);
    if(r<0)return -1;
    s->store_present=r==0;
    if(s->store_present&&iu_trust_store_parse_v1(s->store,s->store_length,&s->store_value))return -1;
    return 0;
}
static int read_stage(struct snapshot *s,uid_t uid,gid_t gid) {
    int r=load_named(s->dir,IU_TRUST_TRANSACTION_STAGE_NAME,uid,gid,s->stage,sizeof(s->stage),&s->stage_length,&s->stage_stat);
    if(r<0)return -1;
    if(r==1)return 1;
    return iu_trust_store_parse_v1(s->stage,s->stage_length,&s->stage_value)?-1:0;
}
static int read_generation(struct snapshot *s,uid_t uid,gid_t gid) {
    int r=load_named(s->dir,"generation.v1",uid,gid,s->generation_bytes,sizeof(s->generation_bytes),&s->generation_length,&s->generation_stat);
    if(r<0)return -1;
    s->generation_present=r==0;
    if(s->generation_present&&iu_trust_generation_parse_v1(s->generation_bytes,s->generation_length,&s->generation))return -1;
    return 0;
}
static int generation_matches(const struct iu_trust_generation_v1 *generation,uint64_t number,const char *digest) {
    return generation->generation==number&&!strcmp(generation->store_sha256,digest);
}
static int same_record(const struct iu_trust_record_v1 *a,const struct iu_trust_record_v1 *b) {
    return a->state==b->state&&!memcmp(a->public_key,b->public_key,sizeof(a->public_key))&&
      !strcmp(a->key_id,b->key_id)&&!strcmp(a->publisher,b->publisher)&&!memcmp(a->reserved,b->reserved,sizeof(a->reserved));
}
static int validate_transition(const struct iu_trust_store_v1 *old,const struct iu_trust_store_v1 *next,unsigned operation) {
    unsigned additions=0,revocations=0;const struct iu_trust_record_v1 *revoked=NULL,*added=NULL;
    if(old->generation==UINT64_MAX||next->generation!=old->generation+1)return -1;
    for(unsigned i=0;i<old->count;i++){
        unsigned j=0;while(j<next->count&&strcmp(old->keys[i].key_id,next->keys[j].key_id))j++;
        if(j==next->count)return -1;
        if(same_record(&old->keys[i],&next->keys[j]))continue;
        if(old->keys[i].state!=IU_TRUST_KEY_ACTIVE||next->keys[j].state!=IU_TRUST_KEY_REVOKED||
           memcmp(old->keys[i].public_key,next->keys[j].public_key,32)||strcmp(old->keys[i].publisher,next->keys[j].publisher)||
           strcmp(old->keys[i].key_id,next->keys[j].key_id))return -1;
        ++revocations;revoked=&next->keys[j];
    }
    for(unsigned j=0;j<next->count;j++){
        unsigned i=0;while(i<old->count&&strcmp(next->keys[j].key_id,old->keys[i].key_id))i++;
        if(i==old->count){if(next->keys[j].state!=IU_TRUST_KEY_ACTIVE)return -1;++additions;added=&next->keys[j];}
    }
    if(operation==IU_TRUST_TX_ADD)return additions==1&&revocations==0&&next->count==old->count+1?0:-1;
    if(operation==IU_TRUST_TX_REVOKE)return additions==0&&revocations==1&&next->count==old->count?0:-1;
    if(operation==IU_TRUST_TX_ROTATE)return additions==1&&revocations==1&&next->count==old->count+1&&revoked&&added&&!strcmp(revoked->publisher,added->publisher)?0:-1;
    return -1;
}
static int classify(struct snapshot *s,uid_t uid,gid_t gid) {
    int txrc,stagerc,gen_tmp_rc=1;char digest[65];struct iu_trust_generation_v1 generation_tmp;
    unsigned char generation_tmp_bytes[IU_TRUST_GENERATION_MAX_BYTES];size_t generation_tmp_length=0;struct stat generation_tmp_stat;
    s->state=REC_NONE;
    if(read_current(s,uid,gid))return -1;
    if(scan_artifacts(s->dir,&s->artifacts))return -1;
    if(read_generation(s,uid,gid))return -1;
    txrc=load_named(s->dir,"transaction.v1",uid,gid,s->journal,sizeof(s->journal),&s->journal_length,&s->journal_stat);
    if(txrc<0)return -1;
    if(txrc==1){
        if(s->artifacts&(ART_STAGE|ART_STAGE_TMP|ART_TX_TMP|ART_GENERATION_TMP)){s->state=REC_UNKNOWN;return 0;}
        if(s->generation_present){if(!s->store_present)return -1;iu_trust_sha256_hex_v1(s->store,s->store_length,digest);if(!generation_matches(&s->generation,s->store_value.generation,digest))return -1;}
        return 0;
    }
    if(iu_trust_transaction_parse_v1(s->journal,s->journal_length,&s->transaction))return -1;
    if(s->artifacts&(ART_STAGE_TMP|ART_TX_TMP))return -1;
    gen_tmp_rc=load_named(s->dir,".generation.tmp",uid,gid,generation_tmp_bytes,sizeof(generation_tmp_bytes),&generation_tmp_length,&generation_tmp_stat);
    if(gen_tmp_rc<0)return -1;
    if(gen_tmp_rc==0&&iu_trust_generation_parse_v1(generation_tmp_bytes,generation_tmp_length,&generation_tmp))return -1;
    stagerc=read_stage(s,uid,gid);
    if(stagerc<0)return -1;
    if(stagerc==0){iu_trust_sha256_hex_v1(s->stage,s->stage_length,digest);if(strcmp(digest,s->transaction.new_store_sha256)||s->stage_value.generation!=s->transaction.new_generation)return -1;}
    if(s->store_present){iu_trust_sha256_hex_v1(s->store,s->store_length,digest);if(s->store_value.generation==s->transaction.new_generation&&!strcmp(digest,s->transaction.new_store_sha256)){
            if(stagerc==0&&(s->stage_length!=s->store_length||memcmp(s->stage,s->store,s->store_length)))return -1;
            if(s->generation_present&&!generation_matches(&s->generation,s->transaction.new_generation,s->transaction.new_store_sha256)&&
               (!s->transaction.old_store_present||!generation_matches(&s->generation,s->transaction.old_generation,s->transaction.old_store_sha256)))return -1;
            if(gen_tmp_rc==0&&!generation_matches(&generation_tmp,s->transaction.new_generation,s->transaction.new_store_sha256))return -1;
            s->state=REC_COMMITTED;return 0;}}
    if(!s->transaction.old_store_present){if(s->store_present||s->transaction.new_generation!=1||s->transaction.operation!=IU_TRUST_TX_ADD||s->stage_value.count!=1||s->stage_value.keys[0].state!=IU_TRUST_KEY_ACTIVE||s->generation_present||gen_tmp_rc==0)return -1;}
    else {if(!s->store_present||s->store_value.generation!=s->transaction.old_generation)return -1;iu_trust_sha256_hex_v1(s->store,s->store_length,digest);if(strcmp(digest,s->transaction.old_store_sha256)||validate_transition(&s->store_value,&s->stage_value,s->transaction.operation))return -1;
        if(s->generation_present&&!generation_matches(&s->generation,s->transaction.old_generation,s->transaction.old_store_sha256))return -1;
        if(gen_tmp_rc==0)return -1;}
    if(stagerc!=0)return -1;
    s->state=REC_PREPARED;return 0;
}
static void print_snapshot(const struct snapshot *s) {
    switch(s->state){case REC_NONE:puts("Trust transaction: none");break;case REC_PREPARED:puts("Trust transaction: prepared; old store and authenticated staged store match the journal");break;case REC_COMMITTED:puts("Trust transaction: new store is committed and matches the journal");break;case REC_UNKNOWN:puts("Trust transaction: unresolved unjournaled stage artifact; evidence preserved");break;case REC_CONFLICT:puts("Trust transaction: conflicting filesystem state; evidence preserved");break;}
    puts("Rollback protection: ROLLBACK_PROTECTION_UNVERIFIED");
    puts("Operational authorization: false");
}
static int cleanup_transaction(struct snapshot *s,uid_t uid,gid_t gid,const char *interrupt) {
    unsigned char check[IU_TRUST_STORE_MAX_BYTES],journal[IU_TRUST_TRANSACTION_MAX_BYTES],generation_bytes[IU_TRUST_GENERATION_MAX_BYTES];size_t n=0,jn=0,gn=0;struct stat st;char digest[65];struct iu_trust_generation_v1 generation;
    if(s->state!=REC_COMMITTED)return -1;
    if(load_named(s->dir,"store.v1",uid,gid,check,sizeof(check),&n,&st)||n!=s->store_length||memcmp(check,s->store,n))return -1;
    iu_trust_sha256_hex_v1(check,n,digest);if(strcmp(digest,s->transaction.new_store_sha256))return -1;
    if(load_named(s->dir,"generation.v1",uid,gid,generation_bytes,sizeof(generation_bytes),&gn,&st)||iu_trust_generation_parse_v1(generation_bytes,gn,&generation)||!generation_matches(&generation,s->transaction.new_generation,s->transaction.new_store_sha256))return -1;
    if(load_named(s->dir,"transaction.v1",uid,gid,journal,sizeof(journal),&jn,&st)||jn!=s->journal_length||memcmp(journal,s->journal,jn))return -1;
    if(s->artifacts&ART_STAGE){unsigned char staged[IU_TRUST_STORE_MAX_BYTES];size_t sn=0;struct stat ss;if(load_named(s->dir,IU_TRUST_TRANSACTION_STAGE_NAME,uid,gid,staged,sizeof(staged),&sn,&ss)||sn!=n||memcmp(staged,check,n))return -1;if(unlinkat(s->dir,IU_TRUST_TRANSACTION_STAGE_NAME,0))return -1;}
#if defined(IU_INSTALLER_TESTING)
    if(interrupt&&!strcmp(interrupt,"trust-during-cleanup"))_exit(86);
#else
    (void)interrupt;
#endif
    if(unlinkat(s->dir,"transaction.v1",0))return -1;
    return syncdir(s->dir);
}
static int ensure_generation_anchor(int dir,uid_t uid,gid_t gid,const struct iu_trust_transaction_v1 *tx,const char *interrupt) {
    unsigned char store[IU_TRUST_STORE_MAX_BYTES],anchor_bytes[IU_TRUST_GENERATION_MAX_BYTES],tmp_bytes[IU_TRUST_GENERATION_MAX_BYTES];
    size_t store_n=0,anchor_n=0,tmp_n=0,encoded_n=0;struct stat store_st,anchor_st,tmp_st;struct iu_trust_store_v1 parsed_store;struct iu_trust_generation_v1 anchor,tmp,expected;char digest[65];int anchor_rc,tmp_rc;
    if(load_named(dir,"store.v1",uid,gid,store,sizeof(store),&store_n,&store_st)||iu_trust_store_parse_v1(store,store_n,&parsed_store))return -1;
    iu_trust_sha256_hex_v1(store,store_n,digest);
    if(parsed_store.generation!=tx->new_generation||strcmp(digest,tx->new_store_sha256))return -1;
    memset(&expected,0,sizeof(expected));expected.generation=tx->new_generation;strcpy(expected.store_sha256,tx->new_store_sha256);
    anchor_rc=load_named(dir,"generation.v1",uid,gid,anchor_bytes,sizeof(anchor_bytes),&anchor_n,&anchor_st);
    if(anchor_rc<0)return -1;
    if(anchor_rc==0){if(iu_trust_generation_parse_v1(anchor_bytes,anchor_n,&anchor))return -1;
        if(!generation_matches(&anchor,tx->new_generation,tx->new_store_sha256)&&
           (!tx->old_store_present||!generation_matches(&anchor,tx->old_generation,tx->old_store_sha256)))return -1;}
    tmp_rc=load_named(dir,".generation.tmp",uid,gid,tmp_bytes,sizeof(tmp_bytes),&tmp_n,&tmp_st);
    if(tmp_rc<0)return -1;
    if(tmp_rc==0&&(iu_trust_generation_parse_v1(tmp_bytes,tmp_n,&tmp)||!generation_matches(&tmp,tx->new_generation,tx->new_store_sha256)))return -1;
    if(anchor_rc==0&&generation_matches(&anchor,tx->new_generation,tx->new_store_sha256)){
        if(tmp_rc==0){if(unlinkat(dir,".generation.tmp",0)||syncdir(dir))return -1;}
        return 0;
    }
    if(tmp_rc==1){
        if(iu_trust_generation_encode_v1(&expected,anchor_bytes,sizeof(anchor_bytes),&encoded_n)||
           write_new_file(dir,".generation.tmp",uid,gid,anchor_bytes,encoded_n,&tmp_st))return -1;
        if(load_named(dir,".generation.tmp",uid,gid,tmp_bytes,sizeof(tmp_bytes),&tmp_n,&tmp_st)||tmp_n!=encoded_n||memcmp(tmp_bytes,anchor_bytes,encoded_n)||iu_trust_generation_parse_v1(tmp_bytes,tmp_n,&tmp)||!generation_matches(&tmp,tx->new_generation,tx->new_store_sha256))return -1;
#if defined(IU_INSTALLER_TESTING)
        if(interrupt&&!strcmp(interrupt,"trust-after-generation-fsync"))_exit(86);
#else
        (void)interrupt;
#endif
    }
    if(renameat(dir,".generation.tmp",dir,"generation.v1")||syncdir(dir))return -1;
    return 0;
}
static int recover(int dir,uid_t uid,gid_t gid,int apply) {
    struct snapshot s;memset(&s,0,sizeof(s));s.dir=dir;
    if(classify(&s,uid,gid)){puts("Trust transaction: corrupt, unsafe, or conflicting; evidence preserved");return 3;}
    print_snapshot(&s);
    if(s.state==REC_NONE)return 0;
    if(s.state==REC_UNKNOWN){puts("Recovery refused: journal authority is absent; inspect the preserved artifacts manually.");return 3;}
    if(s.state!=REC_PREPARED&&s.state!=REC_COMMITTED){puts("Recovery refused: filesystem state is not an authenticated transaction state.");return 3;}
    if(!apply){puts("Read-only recovery inspection; use --apply --confirm to recover.");return 0;}
    if(s.state==REC_PREPARED){unsigned char old[IU_TRUST_STORE_MAX_BYTES];size_t oldn=0;struct stat oldst;int oldrc=load_named(dir,"store.v1",uid,gid,old,sizeof(old),&oldn,&oldst);char digest[65];
        if(s.transaction.old_store_present){if(oldrc||oldn!=s.store_length||memcmp(old,s.store,oldn))return 3;}
        else if(oldrc!=1)return 3;
        {unsigned char journal[IU_TRUST_TRANSACTION_MAX_BYTES];size_t jn;struct stat js;if(load_named(dir,"transaction.v1",uid,gid,journal,sizeof(journal),&jn,&js)||jn!=s.journal_length||memcmp(journal,s.journal,jn))return 3;}
        {unsigned char staged[IU_TRUST_STORE_MAX_BYTES];size_t sn;struct stat ss;if(load_named(dir,IU_TRUST_TRANSACTION_STAGE_NAME,uid,gid,staged,sizeof(staged),&sn,&ss)||sn!=s.stage_length||memcmp(staged,s.stage,sn))return 3;iu_trust_sha256_hex_v1(staged,sn,digest);if(strcmp(digest,s.transaction.new_store_sha256))return 3;}
        if(renameat(dir,IU_TRUST_TRANSACTION_STAGE_NAME,dir,"store.v1"))return 3;
        if(syncdir(dir)){puts("Store rename observed; directory sync failed; journal retained.");return 3;}
        if(ensure_generation_anchor(dir,uid,gid,&s.transaction,NULL)){puts("Store committed but generation anchor update failed; journal retained.");return 3;}
        memset(&s,0,sizeof(s));s.dir=dir;
        if(classify(&s,uid,gid)||s.state!=REC_COMMITTED){puts("Recovered rename did not verify; journal retained.");return 3;}
    }
    if(ensure_generation_anchor(dir,uid,gid,&s.transaction,NULL)){puts("Store verified but generation anchor update failed; journal retained.");return 3;}
    if(cleanup_transaction(&s,uid,gid,NULL)){puts("Verified store retained; transaction cleanup failed and evidence is preserved where present.");return 3;}
    puts("Trust recovery complete: canonical generation and digest verified; execution remains disabled.");return 0;
}
static int prepare_dir(int datafd,uid_t uid,gid_t gid,int *dir) {
    struct stat s;*dir=openat(datafd,"trusted-publishers",O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
    if(*dir>=0)return safe_dir(*dir,uid,gid)?0:-1;
    if(errno!=ENOENT||mkdirat(datafd,"trusted-publishers",0700))return -1;
    *dir=openat(datafd,"trusted-publishers",O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);if(*dir<0)return -1;
    if(fchown(*dir,uid,gid)||fchmod(*dir,0700)||!safe_dir(*dir,uid,gid)||syncdir(datafd)||fstat(*dir,&s))return -1;
    return 0;
}
static int persist_mutation(int dir,uid_t uid,gid_t gid,const unsigned char *old,size_t oldn,int missing,const unsigned char *bytes,size_t n,struct iu_trust_transaction_v1 *tx,const char *interrupt) {
    unsigned char check[IU_TRUST_STORE_MAX_BYTES],jbytes[IU_TRUST_TRANSACTION_MAX_BYTES];size_t checkn=0,jn=0;struct stat oldst,stage_st,jst;int rc;
#if defined(IU_INSTALLER_TESTING)
    if(interrupt&&!strcmp(interrupt,"trust-before-stage-write"))_exit(86);
#else
    (void)interrupt;
#endif
    if(write_new_file(dir,".stage.tmp",uid,gid,bytes,n,&stage_st))return -1;
#if defined(IU_INSTALLER_TESTING)
    if(interrupt&&!strcmp(interrupt,"trust-after-stage-fsync"))_exit(86);
#endif
    {unsigned char staged[IU_TRUST_STORE_MAX_BYTES];size_t sn=0;struct stat ss;if(load_named(dir,".stage.tmp",uid,gid,staged,sizeof(staged),&sn,&ss)||sn!=n||memcmp(staged,bytes,n)||!same(&stage_st,&ss))return -1;}
    if(renameat(dir,".stage.tmp",dir,IU_TRUST_TRANSACTION_STAGE_NAME)||syncdir(dir))return -1;
    if(iu_trust_transaction_encode_v1(tx,jbytes,sizeof(jbytes),&jn))return -1;
    if(write_new_file(dir,".transaction.tmp",uid,gid,jbytes,jn,&jst))return -1;
    {unsigned char saved[IU_TRUST_TRANSACTION_MAX_BYTES];size_t savedn=0;struct stat ss;if(load_named(dir,".transaction.tmp",uid,gid,saved,sizeof(saved),&savedn,&ss)||savedn!=jn||memcmp(saved,jbytes,jn)||!same(&jst,&ss))return -1;}
    if(renameat(dir,".transaction.tmp",dir,"transaction.v1")||syncdir(dir))return -1;
#if defined(IU_INSTALLER_TESTING)
    if(interrupt&&!strcmp(interrupt,"trust-after-journal-fsync"))_exit(86);
#endif
    rc=load_named(dir,"store.v1",uid,gid,check,sizeof(check),&checkn,&oldst);
    if((missing&&rc!=1)||(!missing&&(rc||checkn!=oldn||memcmp(check,old,oldn))))return -1;
    {struct snapshot s;memset(&s,0,sizeof(s));s.dir=dir;if(classify(&s,uid,gid)||s.state!=REC_PREPARED||
        iu_trust_transaction_validate_v1(&s.transaction)||s.journal_length!=jn||memcmp(s.journal,jbytes,jn))return -1;}
#if defined(IU_INSTALLER_TESTING)
    if(interrupt&&!strcmp(interrupt,"trust-before-rename"))_exit(86);
#endif
    if(renameat(dir,IU_TRUST_TRANSACTION_STAGE_NAME,dir,"store.v1"))return -1;
#if defined(IU_INSTALLER_TESTING)
    if(interrupt&&!strcmp(interrupt,"trust-after-rename"))_exit(86);
#endif
    if(syncdir(dir))return -2;
#if defined(IU_INSTALLER_TESTING)
    if(interrupt&&!strcmp(interrupt,"trust-after-dir-fsync"))_exit(86);
#endif
    if(load_named(dir,"store.v1",uid,gid,check,sizeof(check),&checkn,&oldst)||checkn!=n||memcmp(check,bytes,n))return -2;
    {struct iu_trust_store_v1 verify;if(iu_trust_store_parse_v1(check,checkn,&verify)||verify.generation!=tx->new_generation)return -2;}
#if defined(IU_INSTALLER_TESTING)
    if(interrupt&&!strcmp(interrupt,"trust-after-verify"))_exit(86);
#endif
    {struct snapshot s;memset(&s,0,sizeof(s));s.dir=dir;if(classify(&s,uid,gid)||s.state!=REC_COMMITTED||ensure_generation_anchor(dir,uid,gid,&s.transaction,interrupt))return -2;}
#if defined(IU_INSTALLER_TESTING)
    if(interrupt&&!strcmp(interrupt,"trust-after-generation-anchor"))_exit(86);
#endif
    {struct snapshot s;memset(&s,0,sizeof(s));s.dir=dir;if(classify(&s,uid,gid)||s.state!=REC_COMMITTED||cleanup_transaction(&s,uid,gid,interrupt))return -2;}
    return 0;
}

int iu_trust_manager_run(int datafd,uid_t uid,gid_t gid,const char *action,const char *first,const char *second,const char *publisher,int apply,const char *interrupt) {
    struct iu_trust_store_v1 store;struct iu_trust_record_v1 record;struct snapshot snap;unsigned char old[IU_TRUST_STORE_MAX_BYTES],bytes[IU_TRUST_STORE_MAX_BYTES];size_t oldn=0,n;int dir=-1,missing=0,rc;unsigned index;unsigned artifact_mask=0;char digest[65];
    if(!safe_dir(datafd,uid,gid))return 3;
    dir=openat(datafd,"trusted-publishers",O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
    if(dir<0&&errno!=ENOENT)return 3;
    if(dir>=0&&!safe_dir(dir,uid,gid)){close(dir);return 3;}
    if(!strcmp(action,"recover")){
        if(dir<0){puts("Trust transaction: none (trust directory missing)");puts("Rollback protection: ROLLBACK_PROTECTION_UNVERIFIED");puts("Operational authorization: false");return 0;}
        rc=recover(dir,uid,gid,apply);close(dir);return rc;
    }
    if(dir>=0){memset(&snap,0,sizeof(snap));snap.dir=dir;if(classify(&snap,uid,gid)){puts("TRUST_GENERATION_INCONSISTENT or TRUST_TRANSACTION_PENDING: local trust state cannot be established");close(dir);return 3;}if(snap.state!=REC_NONE){puts("TRUST_TRANSACTION_PENDING: use privileged trust recover after reviewing the observed state");print_snapshot(&snap);close(dir);return 3;}}
    memset(&store,0,sizeof(store));store.abi_version=1;store.struct_size=sizeof(store);store.generation=1;
    if(dir>=0){rc=load_named(dir,"store.v1",uid,gid,old,sizeof(old),&oldn,&(struct stat){0});if(rc<0||(rc==0&&iu_trust_store_parse_v1(old,oldn,&store))){close(dir);return 3;}missing=rc==1;}
    else missing=1;
    printf("Trust store: %s; generation=%llu; keys=%u\nROLLBACK_PROTECTION_UNVERIFIED\nOperational authorization: false\n",missing?"missing":"valid",(unsigned long long)(missing?0:store.generation),store.count);
    if(!strcmp(action,"status")||!strcmp(action,"plan")||!strcmp(action,"list")){if(!strcmp(action,"list"))for(unsigned i=0;i<store.count;i++)printf("%s %s %s\n",store.keys[i].key_id,store.keys[i].publisher,store.keys[i].state==IU_TRUST_KEY_ACTIVE?"active":"revoked");if(dir>=0)close(dir);return 0;}
    if(!strcmp(action,"add-key")||!strcmp(action,"rotate-key")){
        if(keyfile(!strcmp(action,"add-key")?first:second,&record,publisher)||store.count==IU_TRUST_STORE_MAX_KEYS){rc=3;goto done;}
        for(unsigned i=0;i<store.count;i++)if(!strcmp(store.keys[i].key_id,record.key_id)){rc=3;goto done;}
    }
    if(!strcmp(action,"revoke-key")||!strcmp(action,"rotate-key")){
        for(index=0;index<store.count;index++)if(!strcmp(store.keys[index].key_id,first))break;
        if(index==store.count){rc=3;goto done;}
        if(!strcmp(action,"rotate-key")&&(store.keys[index].state!=IU_TRUST_KEY_ACTIVE||strcmp(store.keys[index].publisher,publisher))){rc=3;goto done;}
        if(store.keys[index].state==IU_TRUST_KEY_REVOKED){puts("Already revoked; no change.");rc=0;goto done;}
        store.keys[index].state=IU_TRUST_KEY_REVOKED;
    }
    if(!strcmp(action,"add-key")||!strcmp(action,"rotate-key"))store.keys[store.count++]=record;
    if(!missing){if(store.generation==UINT64_MAX){rc=3;goto done;}store.generation++;}
    qsort(store.keys,store.count,sizeof(store.keys[0]),compare);
    if(iu_trust_store_encode_v1(&store,bytes,sizeof(bytes),&n)){rc=3;goto done;}
    printf("Proposed %s: generation=%llu\n",action,(unsigned long long)store.generation);
    if(!apply){puts("Read-only plan; use --apply --confirm.");rc=0;goto done;}
    if(dir<0&&prepare_dir(datafd,uid,gid,&dir)){rc=3;goto done;}
    if(!safe_dir(dir,uid,gid)||scan_artifacts(dir,&artifact_mask)||(artifact_mask&~ART_GENERATION)){puts("Trust directory contains an unresolved or foreign transaction artifact; preserve it for review.");rc=3;goto done;}
    {struct iu_trust_transaction_v1 tx;memset(&tx,0,sizeof(tx));tx.schema_version=1;tx.operation=!strcmp(action,"add-key")?IU_TRUST_TX_ADD:!strcmp(action,"revoke-key")?IU_TRUST_TX_REVOKE:IU_TRUST_TX_ROTATE;tx.phase=IU_TRUST_TX_PREPARED;tx.old_store_present=!missing;tx.old_generation=missing?0:store.generation-1;tx.new_generation=store.generation;if(missing)strcpy(tx.old_store_sha256,"none");else iu_trust_sha256_hex_v1(old,oldn,tx.old_store_sha256);iu_trust_sha256_hex_v1(bytes,n,tx.new_store_sha256);strcpy(tx.stage_name,IU_TRUST_TRANSACTION_STAGE_NAME);if(persist_mutation(dir,uid,gid,old,oldn,missing,bytes,n,&tx,interrupt)){puts("Trust transaction stopped; journal and staged evidence are retained when present. Run trust recover after inspecting observed state.");rc=3;}else{printf("Trust store committed atomically at generation %llu; execution disabled.\n",(unsigned long long)store.generation);rc=0;}}
    (void)digest;
done: if(dir>=0)close(dir);return rc;
}
