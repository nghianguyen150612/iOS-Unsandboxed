#define _POSIX_C_SOURCE 200809L
#include "iu_amethyst_adapter.h"
#include "mock_backend.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static int failures;
#define CHECK(x) do { if (!(x)) { fprintf(stderr,"FAIL %s:%d: %s\n",__FILE__,__LINE__,#x); failures++; } } while (0)

static void put32le(unsigned char *p,uint32_t v){p[0]=(unsigned char)v;p[1]=(unsigned char)(v>>8);p[2]=(unsigned char)(v>>16);p[3]=(unsigned char)(v>>24);}
static void put32be(unsigned char *p,uint32_t v){p[0]=(unsigned char)(v>>24);p[1]=(unsigned char)(v>>16);p[2]=(unsigned char)(v>>8);p[3]=(unsigned char)v;}
static int write_fixture(const char *path,const unsigned char *p,size_t n){int fd=open(path,O_WRONLY|O_CREAT|O_TRUNC,0600);size_t done=0;if(fd<0)return -1;while(done<n){ssize_t k=write(fd,p+done,n-done);if(k<0&&errno==EINTR)continue;if(k<=0){close(fd);return -1;}done+=(size_t)k;}return close(fd);}
static void make_macho(unsigned char *b,size_t *n,uint32_t cpu,uint32_t sig,uint32_t sig_size,uint32_t cd_flags,uint32_t malformed)
{
    memset(b,0,160);put32le(b,UINT32_C(0xfeedfacf));put32le(b+4,cpu);put32le(b+16,1);put32le(b+20,16);
    put32le(b+32,UINT32_C(0x1d));put32le(b+36,16);put32le(b+40,sig);put32le(b+44,sig_size);*n=80;
    if(sig_size==0)return;
    if(sig<48||(uint64_t)sig+(uint64_t)sig_size>160U)return;
    put32be(b+sig,UINT32_C(0xfade0cc0));put32be(b+sig+4,malformed?sig_size-1U:sig_size);put32be(b+sig+8,1);
    put32be(b+sig+12,0);put32be(b+sig+16,20);put32be(b+sig+20,UINT32_C(0xfade0c02));put32be(b+sig+24,72);put32be(b+sig+28,0);put32be(b+sig+32,cd_flags);put32be(b+sig+36,52);put32be(b+sig+40,44);put32be(b+sig+44,0);put32be(b+sig+48,1);put32be(b+sig+52,1);b[sig+56]=20;b[sig+57]=2;b[sig+59]=12;memcpy(b+sig+64,"app",4);*n=sig+sig_size;
}
static void make_policy(struct iu_policy_config_v1 *c,struct iu_policy_target_v1 *t)
{
    const char *dir="/opt/fixture";const char *path="/opt/fixture/app";size_t n;
    memset(c,0,sizeof(*c));c->abi_version=IU_POLICY_ABI_VERSION;c->struct_size=(uint32_t)sizeof(*c);c->enabled=1;c->compatibility_status=IU_COMPAT_SUPPORTED_AND_VERIFIED;c->expected_owner_uid=(uint32_t)geteuid();c->eligible_directory_count=1;
    n=strlen(dir);c->eligible_directories[0].path_length=(uint32_t)n;memcpy(c->eligible_directories[0].path,dir,n+1);c->eligible_directories[0].owner_uid=(uint32_t)geteuid();c->eligible_directories[0].mode=0700;c->eligible_directories[0].file_type=IU_POLICY_FILE_DIRECTORY;c->eligible_directories[0].metadata_verified=1;
    memset(t,0,sizeof(*t));t->abi_version=IU_POLICY_ABI_VERSION;t->struct_size=(uint32_t)sizeof(*t);t->inspection_state=IU_POLICY_INSPECTION_OK;t->file_type=IU_POLICY_FILE_REGULAR;t->owner_uid=(uint32_t)geteuid();t->mode=0100700;t->link_count=1;t->canonical_path_length=(uint32_t)strlen(path);memcpy(t->canonical_path,path,strlen(path)+1);t->path_device=t->descriptor_device=1;t->path_inode=t->descriptor_inode=2;
}
static void test_classification(void)
{
    struct iu_ame_observed_facts_v1 f;struct iu_ame_capability_result_v1 r;
    memset(&f,0,sizeof(f));f.abi_version=IU_AME_ADAPTER_ABI_VERSION;f.struct_size=(uint32_t)sizeof(f);f.system_family=IU_SYSTEM_IOS;f.architecture=IU_ARCH_ARM64;f.reference_device_match=IU_MATCH_YES;f.reference_os_match=IU_MATCH_YES;f.component_present_mask=3;f.component_safe_mask=3;
    CHECK(iu_ame_adapter_classify_v1(&f,&r)==0&&r.compatibility==IU_AME_INSTALLED_BUILD_UNVERIFIED);
    f.source_revision.length=40;memcpy(f.source_revision.value,IU_AME_SOURCE_REVISION,41);CHECK(iu_ame_adapter_classify_v1(&f,&r)==0&&r.compatibility==IU_AME_SOURCE_REVISION_KNOWN);
    memset(&f.source_revision,0,sizeof(f.source_revision));f.reference_device_match=IU_MATCH_NO;f.device_identifier.length=7;memcpy(f.device_identifier.value,"iPad4,1",8);CHECK(iu_ame_adapter_classify_v1(&f,&r)==0&&r.compatibility==IU_AME_UNSUPPORTED_PLATFORM);
    f.reference_device_match=IU_MATCH_YES;f.reference_os_match=IU_MATCH_NO;CHECK(iu_ame_adapter_classify_v1(&f,&r)==0&&r.compatibility==IU_AME_VERSION_MISMATCH);
    f.reference_os_match=IU_MATCH_YES;f.component_present_mask=1;CHECK(iu_ame_adapter_classify_v1(&f,&r)==0&&r.compatibility==IU_AME_COMPONENT_MISSING);
    f.component_present_mask=3;f.build_evidence=IU_AME_BUILD_VERSION_MISMATCH;CHECK(iu_ame_adapter_classify_v1(&f,&r)==0&&r.compatibility==IU_AME_VERSION_MISMATCH);f.build_evidence=IU_AME_BUILD_UNKNOWN;
    f.struct_size--;CHECK(iu_ame_adapter_classify_v1(&f,&r)!=0&&r.compatibility==IU_AME_ABI_INCOMPATIBLE);
    f.struct_size=(uint32_t)sizeof(f);f.abi_version=99;CHECK(iu_ame_adapter_classify_v1(&f,&r)!=0&&r.compatibility==IU_AME_ABI_INCOMPATIBLE);f.abi_version=IU_AME_ADAPTER_ABI_VERSION;
    f.architecture=99;CHECK(iu_ame_adapter_classify_v1(&f,&r)!=0&&r.error_code==IU_AME_ERROR_INVALID_ENUM);
    f.architecture=IU_ARCH_ARM64;f.device_identifier.length=IU_AME_TEXT_CAPACITY;CHECK(iu_ame_adapter_classify_v1(&f,&r)!=0);
    memset(&f.device_identifier,0,sizeof(f.device_identifier));f.reference_os_match=IU_MATCH_NO;f.reference_device_match=IU_MATCH_NO;f.system_family=IU_SYSTEM_LINUX;f.architecture=IU_ARCH_X86_64;f.component_present_mask=3;f.component_safe_mask=3;f.build_evidence=IU_AME_BUILD_TRUSTED_HASH_MATCH;f.launchd_hook_evidence=IU_AME_HOOK_INDEPENDENTLY_VERIFIED;f.base_hook_evidence=IU_AME_HOOK_INDEPENDENTLY_VERIFIED;f.device_evidence_complete=1;f.source_revision.length=40;memcpy(f.source_revision.value,IU_AME_SOURCE_REVISION,41);CHECK(iu_ame_adapter_classify_v1(&f,&r)==0&&r.compatibility==IU_AME_UNSUPPORTED_PLATFORM);
    f.system_family=IU_SYSTEM_IOS;f.architecture=IU_ARCH_ARM64;f.reference_device_match=IU_MATCH_YES;f.reference_os_match=IU_MATCH_YES;CHECK(iu_ame_adapter_classify_v1(&f,&r)==0&&r.compatibility==IU_AME_SUPPORTED_AND_VERIFIED);
}
static void test_components(void)
{
    char dir[]="/tmp/iu-ame-XXXXXX",path[256],linkpath[256],hardpath[256];struct iu_ame_component_evidence_v1 e;unsigned char data[]="abc";char expected[65];static const char hex[]="0123456789abcdef";size_t i;
    CHECK(mkdtemp(dir)!=NULL);snprintf(path,sizeof(path),"%s/component",dir);snprintf(linkpath,sizeof(linkpath),"%s/symlink",dir);snprintf(hardpath,sizeof(hardpath),"%s/hardlink",dir);
    CHECK(write_fixture(path,data,3)==0);CHECK(chmod(path,0700)==0);CHECK(iu_ame_collect_component_v1(IU_AME_COMPONENT_BASE_HOOK,path,&e)==0);CHECK(e.sha256_valid==1&&e.file_type==IU_AME_FILE_REGULAR&&e.link_count==1);
    CHECK(iu_ame_component_evidence_recheck_v1(&e,path)==0);e.sha256[0]^=1U;CHECK(iu_ame_component_evidence_recheck_v1(&e,path)==-IU_AME_ERROR_IDENTITY_MISMATCH);e.sha256[0]^=1U;
    CHECK(write_fixture(path,(const unsigned char *)"abd",3)==0);CHECK(chmod(path,0700)==0);CHECK(iu_ame_component_evidence_recheck_v1(&e,path)==-IU_AME_ERROR_IDENTITY_MISMATCH);CHECK(write_fixture(path,data,3)==0);CHECK(chmod(path,0700)==0);CHECK(iu_ame_component_evidence_recheck_v1(&e,path)==0);
    for(i=0;i<32;i++){expected[i*2]=hex[e.sha256[i]>>4];expected[i*2+1]=hex[e.sha256[i]&15];}expected[64]='\0';CHECK(strcmp(expected,"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")==0);
    CHECK(symlink(path,linkpath)==0);CHECK(iu_ame_collect_component_v1(IU_AME_COMPONENT_BASE_HOOK,linkpath,&e)!=0&&e.file_type==IU_AME_FILE_SYMLINK);
    CHECK(link(path,hardpath)==0);CHECK(iu_ame_collect_component_v1(IU_AME_COMPONENT_BASE_HOOK,path,&e)!=0&&e.file_type==IU_AME_FILE_UNSAFE);unlink(hardpath);
    CHECK(chmod(path,0720)==0);CHECK(iu_ame_collect_component_v1(IU_AME_COMPONENT_BASE_HOOK,path,&e)!=0&&e.file_type==IU_AME_FILE_UNSAFE);
    CHECK(iu_ame_collect_component_v1(IU_AME_COMPONENT_BASE_HOOK,"/not/present/iu-ame",&e)==0&&e.file_type==IU_AME_FILE_MISSING);
    unlink(linkpath);unlink(path);rmdir(dir);
}
static void test_macho(void)
{
    char path[]="/tmp/iu-macho-XXXXXX";int fd=mkstemp(path);unsigned char b[160];size_t n;struct iu_ame_macho_result_v1 r;
    CHECK(fd>=0);if(fd>=0)close(fd);
    make_macho(b,&n,UINT32_C(0x0100000c),48,92,0,0);CHECK(write_fixture(path,b,n)==0);CHECK(iu_ame_macho_inspect_v1(path,&r)==0&&r.state==IU_AME_MACHO_PARSEABLE_CODEDIRECTORY&&r.architecture==IU_ARCH_ARM64);
    make_macho(b,&n,UINT32_C(0x0100000c),48,92,2,0);CHECK(write_fixture(path,b,n)==0);CHECK(iu_ame_macho_inspect_v1(path,&r)==0&&r.state==IU_AME_MACHO_ADHOC_SIGNATURE);
    make_macho(b,&n,UINT32_C(0x0100000c),48,92,0,1);CHECK(write_fixture(path,b,n)==0);CHECK(iu_ame_macho_inspect_v1(path,&r)==0&&r.state==IU_AME_MACHO_MALFORMED_SIGNATURE);
    make_macho(b,&n,UINT32_C(0x0100000c),48,0,0,0);CHECK(write_fixture(path,b,n)==0);CHECK(iu_ame_macho_inspect_v1(path,&r)==0&&r.state==IU_AME_MACHO_EMPTY_SIGNATURE);
    memset(b,0,80);put32le(b,UINT32_C(0xfeedfacf));put32le(b+4,UINT32_C(0x0100000c));CHECK(write_fixture(path,b,80)==0);CHECK(iu_ame_macho_inspect_v1(path,&r)==0&&r.state==IU_AME_MACHO_NO_CODE_SIGNATURE);
    make_macho(b,&n,UINT32_C(0x01000007),48,92,0,0);CHECK(write_fixture(path,b,n)==0);CHECK(iu_ame_macho_inspect_v1(path,&r)==0&&r.state==IU_AME_MACHO_UNSUPPORTED_FORMAT);
    make_macho(b,&n,UINT32_C(0x0100000c),UINT32_C(0xfffffff0),32,0,0);CHECK(write_fixture(path,b,n)==0);CHECK(iu_ame_macho_inspect_v1(path,&r)==0&&r.state==IU_AME_MACHO_EMPTY_SIGNATURE);
    memset(b,0,48);put32le(b,UINT32_C(0xfeedfacf));put32le(b+4,UINT32_C(0x0100000c));put32le(b+16,1);put32le(b+20,16);put32le(b+32,UINT32_C(0x1d));put32le(b+36,4);CHECK(write_fixture(path,b,48)==0);CHECK(iu_ame_macho_inspect_v1(path,&r)==0&&r.state==IU_AME_MACHO_TRUNCATED_OR_CORRUPT);
    CHECK(write_fixture(path,b,8)==0);CHECK(iu_ame_macho_inspect_v1(path,&r)==0&&r.state==IU_AME_MACHO_TRUNCATED_OR_CORRUPT);
    unlink(path);
}
static void test_preview_and_reserved(void)
{
    struct iu_policy_config_v1 config;struct iu_policy_target_v1 target;struct iu_ame_preview_result_v1 mock,real;struct iu_ame_preview_request_v1 request;uint32_t op;
    make_policy(&config,&target);CHECK(iu_test_mock_preview_v1(&config,&target,IU_AME_CAP_SOURCE_CONFIRMED,&mock)==0);CHECK(mock.preview_decision==IU_AME_PREVIEW_HYPOTHETICALLY_ELIGIBLE&&mock.operational_authorization==0);
    config.enabled=0;CHECK(iu_test_mock_preview_v1(&config,&target,IU_AME_CAP_SOURCE_CONFIRMED,&mock)==0&&mock.preview_decision==IU_AME_PREVIEW_BLOCKED&&mock.policy_outcome==IU_POLICY_DENY_DISABLED);config.enabled=1;
    config.compatibility_status=IU_COMPAT_UNVERIFIED;CHECK(iu_test_mock_preview_v1(&config,&target,IU_AME_CAP_SOURCE_CONFIRMED,&mock)==0&&mock.preview_decision==IU_AME_PREVIEW_BLOCKED&&mock.policy_outcome==IU_POLICY_DENY_UNVERIFIED_BACKEND);config.compatibility_status=IU_COMPAT_SUPPORTED_AND_VERIFIED;
    target.descriptor_inode++;CHECK(iu_test_mock_preview_v1(&config,&target,IU_AME_CAP_SOURCE_CONFIRMED,&mock)==0&&mock.preview_decision==IU_AME_PREVIEW_BLOCKED&&mock.policy_outcome==IU_POLICY_DENY_IDENTITY_MISMATCH);target.descriptor_inode--;
    memset(&request,0,sizeof(request));request.abi_version=IU_AME_ADAPTER_ABI_VERSION;request.struct_size=(uint32_t)sizeof(request);request.required_capability=IU_AME_CAP_ARM64_MACHO_INSPECTION;request.policy_config=config;request.target=target;
    CHECK(iu_ame_adapter_preview_v1(&request,&real)==0&&real.preview_decision==IU_AME_PREVIEW_BLOCKED&&real.operational_authorization==0);
    request.reserved_operation=IU_AME_OP_REGISTER_TRUST;CHECK(iu_ame_adapter_preview_v1(&request,&real)==0&&real.preview_decision==IU_AME_PREVIEW_NOT_IMPLEMENTED&&real.policy_outcome==IU_POLICY_DENY_INTERNAL_ERROR&&real.operational_authorization==0);request.reserved_operation=0;
    request.required_capability=0;CHECK(iu_ame_adapter_preview_v1(&request,&real)!=0&&real.blocking_reason==IU_AME_PREVIEW_REASON_INVALID_INPUT);request.required_capability=IU_AME_CAP_ARM64_MACHO_INSPECTION;
    request.abi_version=99;CHECK(iu_ame_adapter_preview_v1(&request,&real)!=0&&real.adapter_compatibility==IU_AME_ABI_INCOMPATIBLE);
    for(op=IU_AME_OP_PREPARE_EXECUTABLE;op<=IU_AME_OP_VERIFY_LAUNCH_BOUNDARY;op++)CHECK(iu_ame_adapter_reserved_operation_v1(op)==IU_AME_ERROR_NOT_IMPLEMENTED);
    CHECK(iu_ame_adapter_reserved_operation_v1(99)<0);
}
int main(void)
{
    struct iu_ame_probe_result_v1 probe;struct iu_ame_capability_set_v1 caps;
    test_classification();test_components();test_macho();test_preview_and_reserved();
    CHECK(iu_ame_adapter_probe_v1(&probe)==0);CHECK(probe.abi_version==IU_AME_ADAPTER_ABI_VERSION);CHECK(probe.compatibility!=IU_AME_SUPPORTED_AND_VERIFIED);CHECK(strcmp(probe.source_revision.value,IU_AME_SOURCE_REVISION)==0);CHECK(probe.reported_package_version.length==0);CHECK(probe.launchd_hook_evidence==IU_AME_HOOK_UNKNOWN);
    CHECK(iu_ame_capabilities_v1(&caps)==0&&caps.record_count==IU_AME_CAPABILITY_COUNT);CHECK(caps.records[0].evidence_type!=IU_AME_EVIDENCE_DEVICE_OBSERVATION);
    if(failures){fprintf(stderr,"adapter fixture failures: %d\n",failures);return 1;}puts("amethyst adapter and capability fixtures: PASS");return 0;
}
