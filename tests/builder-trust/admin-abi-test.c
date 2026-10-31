#define _POSIX_C_SOURCE 200809L
#include "iu_builder_trust_manager.h"
#include <assert.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>
int main(int argc,char **argv) {
    int fd;struct iu_builder_admin_request_v1 r={1,sizeof(r),-1,0,0,0,"status",NULL,NULL,NULL,0};
    if(argc!=2)return 2;
    fd=open(argv[1],O_RDONLY|O_DIRECTORY|O_NOFOLLOW);assert(fd>=0);
    r.datafd=fd;r.uid=geteuid();r.gid=getegid();assert(iu_builder_admin_v1(&r)==0);
    r.abi_version=2;assert(iu_builder_admin_v1(&r)==3);r.abi_version=1;
    r.struct_size--;assert(iu_builder_admin_v1(&r)==3);r.struct_size++;
    r.apply=2;assert(iu_builder_admin_v1(&r)==3);r.apply=0;
    r.reserved=1;assert(iu_builder_admin_v1(&r)==3);r.reserved=0;
    r.uid^=1;assert(iu_builder_admin_v1(&r)==3);r.uid^=1;
    r.gid^=1;assert(iu_builder_admin_v1(&r)==3);r.gid^=1;
    r.action="unknown";assert(iu_builder_admin_v1(&r)==3);
    assert(iu_builder_admin_v1(NULL)==3);
    close(fd);puts("C17/Rust admin ABI v1, foreign UID/GID, unknown requests: PASS");return 0;
}
