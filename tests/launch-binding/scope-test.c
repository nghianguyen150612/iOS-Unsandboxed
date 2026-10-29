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
static void build_document(char *out,size_t cap,const struct iu_execution_plan_v1 *p,const char *origin){static const char hex[]="0123456789abcdef";char hash[65];for(unsigned i=0;i<32;i++){hash[2*i]=hex[p->sha256[i]>>4];hash[2*i+1]=hex[p->sha256[i]&15];}hash[64]=0;assert(snprintf(out,cap,"schema_version=1\nartifact_sha256=%s\nartifact_size=%llu\narchitecture=%u\nfiletype=%u\nsource=manifest\npublisher=fixture-publisher\nbuild=fixture-build\nmanifest=fixture-manifest\nanchor=fixture-anchor\norigin=%s\nalgorithm=fixture-v1\nproof=proof-%s\n",hash,(unsigned long long)p->file_size,p->architecture,p->macho_filetype,origin,origin)>0);}
int main(int argc,char **argv){
    const char *logical="/opt/ios-unsandboxed-scopes/enrolled/innocent";char physical[1024],data[1024],doc[2048],encoded[IU_POLICY_STORE_MAX_BYTES];size_t len;uint64_t dev,ino;int root,datadir,fd,src,storefd;char buf[512];ssize_t got;
    struct iu_policy_store store;struct iu_launch_result_v1 r;struct iu_launch_request_v1 q;
    assert(argc==2);root=open(argv[1],O_RDONLY|O_DIRECTORY);assert(root>=0);assert(snprintf(data,sizeof(data),"%s/data",argv[1])>0);datadir=open(data,O_RDONLY|O_DIRECTORY);assert(datadir>=0);
    assert(iu_policy_scope_inspect(root,"/opt/ios-unsandboxed-scopes/enrolled",getuid(),getgid(),NULL,&dev,&ino,1)==0);
    memset(&store,0,sizeof(store));store.count=1;strcpy(store.scopes[0],"/opt/ios-unsandboxed-scopes/enrolled");store.devices[0]=dev;store.inodes[0]=ino;assert(iu_policy_store_encode(&store,encoded,sizeof(encoded),&len)==0);
    storefd=openat(datadir,"execution-policy",O_CREAT|O_EXCL|O_WRONLY,0600);assert(storefd>=0);assert(write(storefd,encoded,len)==(ssize_t)len);close(storefd);
    /* Copy after enrollment; the fixture models a protected executable but is
       deliberately not a catalog or a real Apple binary. */
    assert(snprintf(physical,sizeof(physical),"%s/parseable",argv[1])>0);src=open(physical,O_RDONLY);assert(src>=0);got=read(src,buf,sizeof(buf));assert(got==140);close(src);
    assert(snprintf(physical,sizeof(physical),"%s%s",argv[1],logical)>0);fd=open(physical,O_CREAT|O_EXCL|O_RDWR,0700);assert(fd>=0);assert(write(fd,buf,(size_t)got)==got);
    memset(&q,0,sizeof(q));q.abi_version=1;q.struct_size=sizeof(q);q.operation=1;q.path_length=(uint32_t)strlen(physical);strcpy(q.path,physical);
    assert(iu_launch_binding_preview_fd_v1(fd,&q,&r)==0);assert(iu_launch_binding_test_scope_v1(root,datadir,getuid(),getgid(),logical,&r)==0);assert(r.scope_state==IU_LAUNCH_SCOPE_MATCH && r.decision==IU_LAUNCH_PROVENANCE_UNKNOWN && !r.operational_authorization);
    build_document(doc,sizeof(doc),&r.artifact,"protected");q.evidence=(const uint8_t *)doc;q.evidence_length=(uint32_t)strlen(doc);
    assert(iu_launch_binding_preview_fd_v1(fd,&q,&r)==0);assert(iu_launch_binding_test_scope_v1(root,datadir,getuid(),getgid(),logical,&r)==0);assert(r.provenance.state==IU_PROVENANCE_PROTECTED_ARTIFACT_KNOWN && r.decision==IU_LAUNCH_KNOWN_PROTECTED && !r.operational_authorization);
    build_document(doc,sizeof(doc),&r.artifact,"unprotected");q.evidence_length=(uint32_t)strlen(doc);assert(iu_launch_binding_preview_fd_v1(fd,&q,&r)==0);assert(iu_launch_binding_test_scope_v1(root,datadir,getuid(),getgid(),logical,&r)==0);assert(r.provenance.state==IU_PROVENANCE_EVIDENCE_VERIFIED && r.decision==IU_LAUNCH_POLICY_DISABLED && !r.operational_authorization);
    { char changed='Q'; assert(pwrite(fd,&changed,1,139)==1); }
    assert(iu_launch_binding_preview_fd_v1(fd,&q,&r)==0);
    assert(r.provenance.state==IU_PROVENANCE_EVIDENCE_IDENTITY_MISMATCH && r.decision==IU_LAUNCH_PROVENANCE_IDENTITY_MISMATCH && !r.operational_authorization);
    assert(iu_launch_binding_test_scope_v1(root,datadir,getuid(),getgid(),"/opt/ios-unsandboxed-scopes/other/app",&r)==0);assert(r.scope_state==IU_LAUNCH_SCOPE_NOT_CONFIGURED);
    store.inodes[0]++;assert(iu_policy_store_encode(&store,encoded,sizeof(encoded),&len)==0);storefd=openat(datadir,"execution-policy",O_TRUNC|O_WRONLY);assert(storefd>=0);assert(write(storefd,encoded,len)==(ssize_t)len);close(storefd);
    assert(iu_launch_binding_test_scope_v1(root,datadir,getuid(),getgid(),logical,&r)==0);assert(r.scope_state==IU_LAUNCH_SCOPE_UNVERIFIED);
    store.inodes[0]=ino;assert(iu_policy_store_encode(&store,encoded,sizeof(encoded),&len)==0);storefd=openat(datadir,"execution-policy",O_TRUNC|O_WRONLY);assert(storefd>=0);assert(write(storefd,encoded,len)==(ssize_t)len);close(storefd);
    assert(iu_launch_binding_test_scope_v1(root,datadir,getuid(),getgid(),logical,&r)==0);assert(r.scope_state==IU_LAUNCH_SCOPE_MATCH);
    assert(snprintf(physical,sizeof(physical),"%s%s",argv[1],logical)>0);assert(unlink(physical)==0);close(fd);
    { char enrolled[1024],retired[1024];assert(snprintf(enrolled,sizeof(enrolled),"%s/opt/ios-unsandboxed-scopes/enrolled",argv[1])>0);assert(snprintf(retired,sizeof(retired),"%s/opt/ios-unsandboxed-scopes/retired",argv[1])>0);
      assert(rename(enrolled,retired)==0);assert(iu_launch_binding_test_scope_v1(root,datadir,getuid(),getgid(),logical,&r)==0);assert(r.scope_state==IU_LAUNCH_SCOPE_UNVERIFIED);
      assert(mkdir(enrolled,0700)==0);assert(iu_launch_binding_test_scope_v1(root,datadir,getuid(),getgid(),logical,&r)==0);assert(r.scope_state==IU_LAUNCH_SCOPE_UNVERIFIED);assert(rmdir(enrolled)==0);
      assert(rename(retired,enrolled)==0); }
    close(datadir);close(root);puts("post-enrollment copy, protected fixture, removed/replaced scope, and policy identity: PASS");return 0;
}
