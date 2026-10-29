#define _DARWIN_C_SOURCE 1
#define _POSIX_C_SOURCE 200809L
#include "iu_trust_manager.h"
#include "iu_trust_store.h"
#include <errno.h>
#include <fcntl.h>
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
static int same(const struct stat *a,const struct stat *b) {
 return a->st_dev==b->st_dev&&a->st_ino==b->st_ino&&a->st_mode==b->st_mode&&a->st_uid==b->st_uid&&a->st_gid==b->st_gid&&a->st_nlink==b->st_nlink&&a->st_size==b->st_size&&a->st_mtime==b->st_mtime&&NS(a,m)==NS(b,m)&&a->st_ctime==b->st_ctime&&NS(a,c)==NS(b,c);
}
static int safe_dir(int fd,uid_t uid,gid_t gid) {struct stat s;return fstat(fd,&s)==0&&S_ISDIR(s.st_mode)&&s.st_uid==uid&&s.st_gid==gid&&(s.st_mode&07777)==0700;}
static int load(int dir,uid_t uid,gid_t gid,unsigned char *bytes,size_t *n,struct stat *identity) {
 struct stat after,path;int fd;size_t pos=0;ssize_t got;
 fd=openat(dir,"store.v1",O_RDONLY|O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC);
 if(fd<0)return errno==ENOENT?1:-1;
 if(fstat(fd,identity)||!S_ISREG(identity->st_mode)||identity->st_uid!=uid||identity->st_gid!=gid||(identity->st_mode&07777)!=0600||identity->st_nlink!=1||identity->st_size<0||identity->st_size>IU_TRUST_STORE_MAX_BYTES){close(fd);return -1;}
 while(pos<IU_TRUST_STORE_MAX_BYTES){got=read(fd,bytes+pos,IU_TRUST_STORE_MAX_BYTES-pos);if(got<0&&errno==EINTR)continue;if(got<0){close(fd);return -1;}if(!got)break;pos+=(size_t)got;}
 if(fstat(fd,&after)||fstatat(dir,"store.v1",&path,AT_SYMLINK_NOFOLLOW)||!same(identity,&after)||!same(identity,&path)||pos!=(size_t)identity->st_size){close(fd);return -1;}
 close(fd);*n=pos;return 0;
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
static int syncdir(int fd){return fsync(fd)==0||errno==EINVAL?0:-1;}
static int persist(int dir,uid_t uid,gid_t gid,const unsigned char *old,size_t oldn,int missing,const struct stat *identity,const unsigned char *bytes,size_t n,int interrupt) {
 unsigned char check[IU_TRUST_STORE_MAX_BYTES];size_t checkn=0,pos=0;struct stat current,temp;char name[96];int fd,rc;
 if(snprintf(name,sizeof(name),".trust-tmp-%ld",(long)getpid())>=(int)sizeof(name))return -1;
 fd=openat(dir,name,O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0600);if(fd<0)return -1;
 if(fchown(fd,uid,gid)||fchmod(fd,0600)){close(fd);return -1;}
 while(pos<n){ssize_t w=write(fd,bytes+pos,n-pos);if(w<0&&errno==EINTR)continue;if(w<=0){close(fd);return -1;}pos+=(size_t)w;}
 if(fsync(fd)||fstat(fd,&temp)||temp.st_nlink!=1||temp.st_uid!=uid||temp.st_gid!=gid||(temp.st_mode&07777)!=0600){close(fd);return -1;}
 if(close(fd))return -1;
 rc=load(dir,uid,gid,check,&checkn,&current);
 if((missing&&rc!=1)||(!missing&&(rc||!same(identity,&current)||checkn!=oldn||memcmp(check,old,oldn))))return -1;
 if(!safe_dir(dir,uid,gid)||fstatat(dir,name,&current,AT_SYMLINK_NOFOLLOW)||!same(&temp,&current))return -1;
#ifdef IU_INSTALLER_TESTING
 if(interrupt)_exit(86);
#else
 (void)interrupt;
#endif
 if(renameat(dir,name,dir,"store.v1"))return -1;
 if(syncdir(dir))return -2;
 if(load(dir,uid,gid,check,&checkn,&current)||checkn!=n||memcmp(check,bytes,n))return -2;
 return 0;
}
int iu_trust_manager_run(int datafd,uid_t uid,gid_t gid,const char *action,const char *first,const char *second,const char *publisher,int apply,int interrupt) {
 struct iu_trust_store_v1 store;struct iu_trust_record_v1 record;struct stat identity,ds,path;unsigned char old[IU_TRUST_STORE_MAX_BYTES],bytes[IU_TRUST_STORE_MAX_BYTES];size_t oldn=0,n;int dir,missing=0,rc;unsigned index;
 if(!safe_dir(datafd,uid,gid))return 3;
 dir=openat(datafd,"trusted-publishers",O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
 if(dir<0){if(errno!=ENOENT)return 3;missing=1;}else if(!safe_dir(dir,uid,gid)){close(dir);return 3;}
 memset(&store,0,sizeof(store));store.abi_version=1;store.struct_size=sizeof(store);store.generation=1;
 if(dir>=0){rc=load(dir,uid,gid,old,&oldn,&identity);if(rc<0||(rc==0&&iu_trust_store_parse_v1(old,oldn,&store))){close(dir);return 3;}missing=rc==1;}
 printf("Trust store: %s; generation=%llu; keys=%u\nROLLBACK_PROTECTION_UNVERIFIED\nOperational authorization: false\n",missing?"missing":"valid",(unsigned long long)(missing?0:store.generation),store.count);
 if(!strcmp(action,"status")||!strcmp(action,"plan")||!strcmp(action,"list")){if(!strcmp(action,"list"))for(unsigned i=0;i<store.count;i++)printf("%s %s %s\n",store.keys[i].key_id,store.keys[i].publisher,store.keys[i].state==IU_TRUST_KEY_ACTIVE?"active":"revoked");rc=0;goto done;}
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
 if(dir<0){if(mkdirat(datafd,"trusted-publishers",0700)){rc=3;goto done;}dir=openat(datafd,"trusted-publishers",O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);if(dir<0){rc=3;goto done;}if(fchown(dir,uid,gid)||fchmod(dir,0700)||syncdir(datafd)){rc=3;goto done;}}
 if(!safe_dir(dir,uid,gid)||fstat(dir,&ds)||fstatat(datafd,"trusted-publishers",&path,AT_SYMLINK_NOFOLLOW)||!same(&ds,&path)){rc=3;goto done;}
 rc=persist(dir,uid,gid,old,oldn,missing,&identity,bytes,n,interrupt);
 if(!rc&&(fstatat(datafd,"trusted-publishers",&path,AT_SYMLINK_NOFOLLOW)||path.st_dev!=ds.st_dev||path.st_ino!=ds.st_ino||!safe_dir(dir,uid,gid)))rc=-2;
 if(rc==-2)puts("Rename committed; verification or directory sync failed. Inspect observed store before retrying.");
 else if(!rc)puts("Trust store committed atomically; execution disabled.");
 rc=rc?3:0;
 done: if(dir>=0)close(dir);return rc;
}
