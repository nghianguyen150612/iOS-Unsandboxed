#if defined(__APPLE__)
#define _DARWIN_C_SOURCE 1
#endif
#define _POSIX_C_SOURCE 200809L
#include "iu_launch_binding.h"
#include "iu_policy_store.h"
#include <fcntl.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#if defined(__APPLE__)
#define MTNS(s) ((s).st_mtimespec.tv_nsec)
#define CTNS(s) ((s).st_ctimespec.tv_nsec)
#else
#define MTNS(s) ((s).st_mtim.tv_nsec)
#define CTNS(s) ((s).st_ctim.tv_nsec)
#endif
#ifndef O_CLOEXEC
#define O_CLOEXEC 0
#endif
static int matches(const struct stat *s, const struct iu_execution_plan_v1 *p) {
    return S_ISREG(s->st_mode) && s->st_nlink==1 && s->st_size>=0 &&
        (uint64_t)s->st_dev==p->device_number && (uint64_t)s->st_ino==p->inode &&
        (uint64_t)s->st_size==p->file_size && (uint32_t)s->st_uid==p->owner_uid &&
        (uint32_t)s->st_gid==p->owner_gid && (uint32_t)(s->st_mode & 07777)==p->mode &&
        (uint32_t)s->st_nlink==p->link_count && (int64_t)s->st_mtime==p->modification_seconds &&
        (uint32_t)MTNS(*s)==p->modification_nanoseconds && (int64_t)s->st_ctime==p->change_seconds &&
        (uint32_t)CTNS(*s)==p->change_nanoseconds;
}
static void scope(int rootfd,int datafd,uid_t uid,gid_t gid,const char *path,struct iu_launch_result_v1 *r) {
    struct iu_policy_store store, second; uint64_t dev,ino; struct stat before, after, atpath; int file;
    r->scope_state=IU_LAUNCH_SCOPE_UNVERIFIED;r->scope_device=0;r->scope_inode=0;r->store_device=0;r->store_inode=0;
    memset(r->scope_path,0,sizeof(r->scope_path));memset(r->store_sha256,0,sizeof(r->store_sha256));
    if (iu_policy_store_load(datafd,uid,gid,&store)!=0) return;
    r->store_state=store.state;
    if (store.state!=IU_STORE_VALID || store.schema!=1 || rootfd<0) return;
    file=openat(datafd,"execution-policy",O_RDONLY|O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC);
    if(file<0)return;
    if(fstat(file,&before)!=0 || iu_ame_sha256_fd_v1(file,r->store_sha256)!=0 || fstat(file,&after)!=0 ||
       fstatat(datafd,"execution-policy",&atpath,AT_SYMLINK_NOFOLLOW)!=0 ||
       before.st_dev!=after.st_dev || before.st_ino!=after.st_ino || before.st_dev!=atpath.st_dev || before.st_ino!=atpath.st_ino ||
       iu_policy_store_load(datafd,uid,gid,&second)!=0 || memcmp(&store,&second,sizeof(store))!=0) {
        close(file);memset(r->store_sha256,0,sizeof(r->store_sha256));return;
    }
    close(file);r->store_device=(uint64_t)before.st_dev;r->store_inode=(uint64_t)before.st_ino;
    r->scope_state=IU_LAUNCH_SCOPE_NOT_CONFIGURED;
    for(unsigned i=0;i<store.count;i++) {
        size_t n=strlen(store.scopes[i]);
        if(iu_policy_scope_inspect(rootfd,store.scopes[i],uid,gid,NULL,&dev,&ino,0)!=0 || dev!=store.devices[i] || ino!=store.inodes[i]) {r->scope_state=IU_LAUNCH_SCOPE_UNVERIFIED;return;}
        if(strncmp(path,store.scopes[i],n)==0 && path[n]=='/') {
            char parent[IU_POLICY_PATH_CAPACITY]; char *slash;
            if(strlen(path)>=sizeof(parent)){r->scope_state=IU_LAUNCH_SCOPE_UNVERIFIED;return;}
            strcpy(parent,path);slash=strrchr(parent,'/');if(!slash){r->scope_state=IU_LAUNCH_SCOPE_UNVERIFIED;return;}*slash='\0';
            if(iu_policy_scope_inspect(rootfd,parent,uid,gid,NULL,NULL,NULL,0)!=0){r->scope_state=IU_LAUNCH_SCOPE_UNVERIFIED;return;}
            r->scope_state=IU_LAUNCH_SCOPE_MATCH;r->scope_device=dev;r->scope_inode=ino;strcpy(r->scope_path,store.scopes[i]);
        }
    }
}
static void production_scope(const char *path,struct iu_launch_result_v1 *r) {
    int rootfd=open("/",O_RDONLY|O_DIRECTORY|O_CLOEXEC);
    int varfd=open("/var/lib",O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
    int datafd=varfd<0?-1:openat(varfd,"ios-unsandboxed",O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
    /* A failed open may mean permission denied; never infer a missing scope. */
    if(datafd>=0) scope(rootfd,datafd,0,0,path,r);
    else {r->scope_state=IU_LAUNCH_SCOPE_UNVERIFIED;r->store_state=IU_STORE_IO_ERROR;}
    if(datafd>=0)close(datafd);
    if(varfd>=0)close(varfd);
    if(rootfd>=0)close(rootfd);
}
/* P003's enabled/verified settings here are deliberately hypothetical, solely
 * to classify protected paths and scope. Operational P003 remains disabled. */
static uint32_t hypothetical_p003(const struct iu_launch_result_v1 *r) {
    struct iu_policy_config_v1 c;struct iu_policy_target_v1 t;struct iu_policy_result_v1 result;
    memset(&c,0,sizeof(c));c.abi_version=IU_POLICY_ABI_VERSION;c.struct_size=sizeof(c);c.enabled=1;c.compatibility_status=IU_COMPAT_SUPPORTED_AND_VERIFIED;c.expected_owner_uid=0;c.eligible_directory_count=1;
    strcpy(c.eligible_directories[0].path,"/opt/ios-unsandboxed-scopes/hypothetical");
    c.eligible_directories[0].path_length=(uint32_t)strlen(c.eligible_directories[0].path);
    c.eligible_directories[0].owner_uid=0;c.eligible_directories[0].mode=0700;c.eligible_directories[0].file_type=IU_POLICY_FILE_DIRECTORY;c.eligible_directories[0].metadata_verified=1;
    if(r->scope_state==IU_LAUNCH_SCOPE_MATCH){strcpy(c.eligible_directories[0].path,r->scope_path);c.eligible_directories[0].path_length=(uint32_t)strlen(r->scope_path);}
    if(iu_policy_inspect_path_v1(r->artifact.canonical_path,r->artifact.canonical_path_length,&t)!=0)return IU_POLICY_DENY_INTERNAL_ERROR;
    if(t.descriptor_device!=r->artifact.device_number || t.descriptor_inode!=r->artifact.inode)return IU_POLICY_DENY_IDENTITY_MISMATCH;
    if(iu_policy_evaluate_v1(&c,&t,&result)!=0)return IU_POLICY_DENY_INTERNAL_ERROR;
    return result.outcome;
}
static void decide(struct iu_launch_result_v1 *r) {
    if(r->hypothetical_p003_outcome==IU_POLICY_DENY_PROTECTED_PATH || r->provenance.state==IU_PROVENANCE_PROTECTED_ARTIFACT_KNOWN)r->decision=IU_LAUNCH_KNOWN_PROTECTED;
    else if(r->provenance.state==IU_PROVENANCE_EVIDENCE_IDENTITY_MISMATCH)r->decision=IU_LAUNCH_PROVENANCE_IDENTITY_MISMATCH;
    else if(r->scope_state!=IU_LAUNCH_SCOPE_MATCH)r->decision=IU_LAUNCH_DECISION_SCOPE_NOT_CONFIGURED;
    else if(r->artifact.architecture!=IU_ARCH_ARM64 || r->artifact.macho_filetype!=2 || r->artifact.macho_state==IU_AME_MACHO_UNSUPPORTED_FORMAT || r->artifact.macho_state==IU_AME_MACHO_TRUNCATED_OR_CORRUPT || r->artifact.macho_state==IU_AME_MACHO_IO_ERROR)r->decision=IU_LAUNCH_UNSUPPORTED_ARTIFACT;
    else if(r->provenance.state==IU_PROVENANCE_EVIDENCE_ABSENT)r->decision=IU_LAUNCH_PROVENANCE_UNKNOWN;
    else if(r->provenance.state!=IU_PROVENANCE_EVIDENCE_VERIFIED || r->provenance.protected_classification!=IU_ORIGIN_UNPROTECTED)r->decision=IU_LAUNCH_ORIGIN_NOT_AUTHENTICATED;
    else r->decision=IU_LAUNCH_POLICY_DISABLED;
}
int32_t iu_launch_binding_preview_fd_v1(int fd,const struct iu_launch_request_v1 *q,struct iu_launch_result_v1 *r) {
    struct stat s; struct iu_ame_macho_result_v1 macho; uint8_t hash[32];
    if(!r)return -1;
    memset(r,0,sizeof(*r));r->abi_version=IU_LAUNCH_BINDING_ABI_VERSION;r->struct_size=sizeof(*r);r->boundary_status=IU_LAUNCH_BOUNDARY_NOT_IMPLEMENTED;r->decision=IU_LAUNCH_POLICY_DISABLED;
    if(!q || q->abi_version!=IU_LAUNCH_BINDING_ABI_VERSION || q->struct_size!=sizeof(*q) || q->operation!=IU_LAUNCH_OPERATION_PREVIEW || q->path_length==0 || q->path_length>=sizeof(q->path) || q->path[q->path_length]!='\0' || memchr(q->path,'\0',q->path_length) || q->evidence_length>IU_PROVENANCE_EVIDENCE_MAX || (!q->evidence && q->evidence_length)) return -1;
    r->operation=q->operation;memcpy(r->requested_path,q->path,(size_t)q->path_length+1);
    if(fstat(fd,&s)!=0 || !S_ISREG(s.st_mode) || s.st_nlink!=1 || s.st_size<0 || (uint64_t)s.st_size>IU_AME_MAX_FILE_SIZE) return -2;
    if(iu_execution_plan_create_v1(q->path,&r->artifact)!=0 || !matches(&s,&r->artifact))return -2;
    if(iu_ame_macho_inspect_fd_v1(fd,&macho)!=0 || iu_ame_sha256_fd_v1(fd,hash)!=0 || fstat(fd,&s)!=0 || !matches(&s,&r->artifact) || memcmp(hash,r->artifact.sha256,32) || macho.state!=r->artifact.macho_state || macho.architecture!=r->artifact.architecture || macho.macho_filetype!=r->artifact.macho_filetype || iu_execution_plan_revalidate_v1(&r->artifact)!=0) return -2;
    r->evidence_length=q->evidence_length;if(q->evidence_length)memcpy(r->evidence,q->evidence,q->evidence_length);
    if(iu_provenance_verify_v1(r->evidence,r->evidence_length,&r->artifact,&r->provenance)!=0)return -1;
    production_scope(r->artifact.canonical_path,r);r->hypothetical_p003_outcome=hypothetical_p003(r);
    decide(r);
    return 0;
}
int32_t iu_launch_binding_revalidate_fd_v1(int fd,const struct iu_launch_result_v1 *p,const uint8_t *evidence,uint32_t length) {
    struct stat s;uint8_t hash[32];struct iu_launch_result_v1 scope_now;struct iu_execution_plan_v1 current;struct iu_provenance_result_v1 provenance_now;
    if(!p || p->abi_version!=IU_LAUNCH_BINDING_ABI_VERSION || p->struct_size!=sizeof(*p) || p->operation!=IU_LAUNCH_OPERATION_PREVIEW || p->boundary_status!=IU_LAUNCH_BOUNDARY_NOT_IMPLEMENTED || p->operational_authorization!=0 || p->scope_state>IU_LAUNCH_SCOPE_MATCH || p->decision<IU_LAUNCH_POLICY_DISABLED || p->decision>IU_LAUNCH_UNSUPPORTED_ARTIFACT || p->store_state>IU_STORE_IO_ERROR || p->hypothetical_p003_outcome>IU_POLICY_DENY_INTERNAL_ERROR || p->provenance.abi_version!=IU_ARTIFACT_PROVENANCE_ABI_VERSION || p->provenance.struct_size!=sizeof(p->provenance) || p->provenance.state>IU_PROVENANCE_UNVERIFIED || p->provenance.reason>IU_PROVENANCE_REASON_PROTECTED || p->provenance.source>IU_PROVENANCE_SOURCE_MANIFEST || p->provenance.protected_classification>IU_ORIGIN_UNPROTECTED || p->evidence_length>IU_PROVENANCE_EVIDENCE_MAX || length>IU_PROVENANCE_EVIDENCE_MAX || (!evidence && length)) return -1;
    if(p->artifact.abi_version!=IU_EXECUTION_PLAN_ABI_VERSION || p->artifact.struct_size!=sizeof(p->artifact) || p->artifact.canonical_path_length<2 || p->artifact.canonical_path_length>=sizeof(p->artifact.canonical_path) || p->artifact.canonical_path[p->artifact.canonical_path_length]!='\0' || memchr(p->artifact.canonical_path,'\0',p->artifact.canonical_path_length) || !memchr(p->scope_path,'\0',sizeof(p->scope_path)))return -1;
    if(iu_execution_plan_revalidate_v1(&p->artifact)==-IU_EXECUTION_PLAN_ERROR_ABI)return -1;
    if(fstat(fd,&s)!=0 || !S_ISREG(s.st_mode))return IU_LAUNCH_IDENTITY_UNVERIFIED;
    if((uint64_t)s.st_dev!=p->artifact.device_number || (uint64_t)s.st_ino!=p->artifact.inode)return IU_LAUNCH_IDENTITY_UNVERIFIED;
    { struct stat pathstat;
      if(lstat(p->artifact.canonical_path,&pathstat)!=0 || !S_ISREG(pathstat.st_mode) || pathstat.st_dev!=s.st_dev || pathstat.st_ino!=s.st_ino)return IU_LAUNCH_PATH_REPLACED;
    }
    if(!matches(&s,&p->artifact) || iu_ame_sha256_fd_v1(fd,hash)!=0 || fstat(fd,&s)!=0 || !matches(&s,&p->artifact) || memcmp(hash,p->artifact.sha256,32))return IU_LAUNCH_OBJECT_MODIFIED;
    if(iu_execution_plan_create_v1(p->artifact.canonical_path,&current)!=0 || current.device_number!=p->artifact.device_number || current.inode!=p->artifact.inode)return IU_LAUNCH_PATH_REPLACED;
    if(iu_execution_plan_revalidate_v1(&p->artifact)!=0)return IU_LAUNCH_OBJECT_MODIFIED;
    if(length!=p->evidence_length || (length && memcmp(evidence,p->evidence,length)))return IU_LAUNCH_STALE_EVIDENCE;
    if(iu_provenance_verify_v1(evidence,length,&p->artifact,&provenance_now)!=0 || memcmp(&provenance_now,&p->provenance,sizeof(provenance_now)))return IU_LAUNCH_STALE_EVIDENCE;
    memset(&scope_now,0,sizeof(scope_now));production_scope(p->artifact.canonical_path,&scope_now);
    if(scope_now.scope_state!=p->scope_state || scope_now.store_state!=p->store_state || scope_now.scope_device!=p->scope_device || scope_now.scope_inode!=p->scope_inode || scope_now.store_device!=p->store_device || scope_now.store_inode!=p->store_inode || memcmp(scope_now.store_sha256,p->store_sha256,32) || memcmp(scope_now.scope_path,p->scope_path,sizeof(p->scope_path)))return IU_LAUNCH_STALE_POLICY;
    return IU_LAUNCH_SAME_OPEN_OBJECT;
}
int32_t iu_launch_binding_path_summary_v1(const char *path,struct iu_launch_cli_summary_v1 *s) {
    struct iu_launch_request_v1 q;struct iu_launch_result_v1 r;size_t n;int fd,rc;
    if(!path || !s)return -1;
    n=strnlen(path,IU_POLICY_PATH_CAPACITY);
    if(!n || n>=IU_POLICY_PATH_CAPACITY)return -1;
    memset(s,0,sizeof(*s));s->abi_version=IU_LAUNCH_BINDING_ABI_VERSION;s->struct_size=sizeof(*s);
    memset(&q,0,sizeof(q));q.abi_version=IU_LAUNCH_BINDING_ABI_VERSION;q.struct_size=sizeof(q);q.operation=IU_LAUNCH_OPERATION_PREVIEW;q.path_length=(uint32_t)n;memcpy(q.path,path,n+1);
    fd=open(path,O_RDONLY|O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC);if(fd<0)return -2;
    rc=iu_launch_binding_preview_fd_v1(fd,&q,&r);close(fd);if(rc)return rc;
    s->scope_state=r.scope_state;s->store_state=r.store_state;s->provenance_state=r.provenance.state;s->decision=r.decision;s->boundary_status=r.boundary_status;s->operational_authorization=r.operational_authorization;s->device=r.artifact.device_number;s->inode=r.artifact.inode;memcpy(s->sha256,r.artifact.sha256,32);return 0;
}
#ifdef IU_LAUNCH_BINDING_TESTING
int32_t iu_launch_binding_test_scope_v1(int rootfd,int datafd,uint32_t uid,uint32_t gid,const char *path,struct iu_launch_result_v1 *r){if(!path||!r)return -1;scope(rootfd,datafd,(uid_t)uid,(gid_t)gid,path,r);decide(r);return 0;}
#endif
