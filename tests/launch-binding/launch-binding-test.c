#define _POSIX_C_SOURCE 200809L
#include "iu_launch_binding.h"
#include "iu_policy_store.h"
#include <assert.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
static void path(char *out,size_t n,const char *root,const char *name){assert(snprintf(out,n,"%s/%s",root,name)>0);}
static int preview(const char *name,struct iu_launch_result_v1 *r){struct iu_launch_request_v1 q;int fd;memset(&q,0,sizeof(q));q.abi_version=1;q.struct_size=sizeof(q);q.operation=1;q.path_length=(uint32_t)strlen(name);strcpy(q.path,name);fd=open(name,O_RDONLY|O_NONBLOCK);assert(fd>=0);int rc=iu_launch_binding_preview_fd_v1(fd,&q,r);close(fd);return rc;}
int main(int argc,char **argv){
    char p[1024],other[1024],old[1024],symlink_path[1024],hard[1024];struct iu_launch_request_v1 q;struct iu_launch_result_v1 r;int fd,fd2;char byte='Z';
    assert(argc==2);path(p,sizeof(p),argv[1],"parseable");fd=open(p,O_RDONLY);assert(fd>=0);
    memset(&q,0,sizeof(q));q.abi_version=1;q.struct_size=sizeof(q);q.operation=1;q.path_length=(uint32_t)strlen(p);strcpy(q.path,p);
    assert(iu_launch_binding_preview_fd_v1(fd,&q,&r)==0);assert(r.operational_authorization==0 && r.artifact.policy_outcome==IU_POLICY_DENY_DISABLED && r.boundary_status==IU_LAUNCH_BOUNDARY_NOT_IMPLEMENTED && r.provenance.state==IU_PROVENANCE_EVIDENCE_ABSENT);
    assert(r.artifact.macho_state==IU_AME_MACHO_PARSEABLE_CODEDIRECTORY && r.artifact.adapter_compatibility!=IU_AME_SUPPORTED_AND_VERIFIED);
    assert(iu_launch_binding_revalidate_fd_v1(fd,&r,NULL,0)==IU_LAUNCH_SAME_OPEN_OBJECT);
    assert(iu_launch_binding_revalidate_fd_v1(fd,&r,(const uint8_t *)"x",1)==IU_LAUNCH_STALE_EVIDENCE);
    path(other,sizeof(other),argv[1],"unsigned");fd2=open(other,O_RDONLY);assert(fd2>=0);assert(iu_launch_binding_revalidate_fd_v1(fd2,&r,NULL,0)==IU_LAUNCH_IDENTITY_UNVERIFIED);close(fd2);
    q.operation=99;assert(iu_launch_binding_preview_fd_v1(fd,&q,&r)<0);q.operation=1;q.struct_size--;assert(iu_launch_binding_preview_fd_v1(fd,&q,&r)<0);q.struct_size++;
    assert(iu_launch_binding_preview_fd_v1(fd,&q,&r)==0);r.operational_authorization=1;assert(iu_launch_binding_revalidate_fd_v1(fd,&r,NULL,0)<0);r.operational_authorization=0;r.scope_state=99;assert(iu_launch_binding_revalidate_fd_v1(fd,&r,NULL,0)<0);r.scope_state=IU_LAUNCH_SCOPE_UNVERIFIED;
    fd2=open(p,O_WRONLY);assert(fd2>=0);assert(pwrite(fd2,&byte,1,139)==1);close(fd2);assert(iu_launch_binding_revalidate_fd_v1(fd,&r,NULL,0)==IU_LAUNCH_OBJECT_MODIFIED);close(fd);
    path(p,sizeof(p),argv[1],"adhoc");fd=open(p,O_RDONLY);assert(fd>=0);q.path_length=(uint32_t)strlen(p);strcpy(q.path,p);assert(iu_launch_binding_preview_fd_v1(fd,&q,&r)==0);
    path(old,sizeof(old),argv[1],"old");assert(rename(p,old)==0);fd2=open(p,O_CREAT|O_WRONLY|O_EXCL,0700);assert(fd2>=0);assert(write(fd2,"different",9)==9);close(fd2);assert(iu_launch_binding_revalidate_fd_v1(fd,&r,NULL,0)==IU_LAUNCH_PATH_REPLACED);close(fd);
    path(p,sizeof(p),argv[1],"unsigned");path(hard,sizeof(hard),argv[1],"hard");assert(link(p,hard)==0);assert(preview(p,&r)!=0);assert(unlink(hard)==0);
    path(symlink_path,sizeof(symlink_path),argv[1],"alias");assert(symlink(p,symlink_path)==0);assert(preview(symlink_path,&r)!=0);
    path(p,sizeof(p),argv[1],"fifo");assert(preview(p,&r)!=0);
    path(p,sizeof(p),argv[1],"malformed");fd=open(p,O_RDONLY);assert(fd>=0);q.path_length=(uint32_t)strlen(p);strcpy(q.path,p);assert(iu_launch_binding_preview_fd_v1(fd,&q,&r)==0);assert(chmod(p,0600)==0);assert(iu_launch_binding_revalidate_fd_v1(fd,&r,NULL,0)==IU_LAUNCH_OBJECT_MODIFIED);assert(chmod(p,0700)==0);close(fd);
    path(p,sizeof(p),argv[1],"wrong-architecture");assert(preview(p,&r)==0);assert(r.artifact.architecture!=IU_ARCH_ARM64 && r.operational_authorization==0);
    path(p,sizeof(p),argv[1],"malformed");assert(preview(p,&r)==0);assert(r.artifact.macho_state==IU_AME_MACHO_MALFORMED_SIGNATURE && r.operational_authorization==0);
    path(p,sizeof(p),argv[1],"unsigned");assert(preview(p,&r)==0);assert(r.artifact.macho_state==IU_AME_MACHO_NO_CODE_SIGNATURE && r.operational_authorization==0);
    puts("descriptor binding, mutation, and replacement: PASS");return 0;
}
