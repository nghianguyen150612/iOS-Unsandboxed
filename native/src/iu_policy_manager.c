#define _GNU_SOURCE 1
#define _DARWIN_C_SOURCE 1
#include "iu_policy_manager.h"
#include "iu_execution_planner.h"
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

int iu_policy_preview(const struct iu_policy_store *s,int rootfd,const char *root,int fixture,uid_t uid,gid_t gid,const char *target) {
    struct iu_policy_config_v1 config; struct iu_policy_target_v1 facts;
    struct iu_policy_result_v1 simulated,operational; struct iu_execution_plan_v1 plan;
    char physical[IU_POLICY_PATH_CAPACITY],parent[IU_POLICY_PATH_CAPACITY]; const char *reason="UNSAFE_TARGET"; char *slash; int matched=0;
    memset(&config,0,sizeof(config));config.abi_version=IU_POLICY_ABI_VERSION;config.struct_size=sizeof(config);
    config.expected_owner_uid=(uint32_t)uid; config.eligible_directory_count=s->count;
    for(unsigned i=0;i<s->count;i++) {
        struct iu_policy_directory_v1 d; uint64_t dev,ino;
        if(iu_policy_scope_inspect(rootfd,s->scopes[i],uid,gid,&d,&dev,&ino,0)!=0 || dev!=s->devices[i] || ino!=s->inodes[i]){reason="UNSAFE_DIRECTORY";goto report;}
        if(fixture){int n=snprintf(d.path,sizeof(d.path),"%s%s",root,s->scopes[i]);if(n<0||(size_t)n>=sizeof(d.path)){reason="UNSAFE_DIRECTORY";goto report;}d.path_length=(uint32_t)n;}
        config.eligible_directories[i]=d;
        {size_t n=strlen(s->scopes[i]); if(strncmp(target,s->scopes[i],n)==0 && target[n]=='/')matched=1;}
    }
    if(s->count==0){reason="NOT_CONFIGURED";goto report;}
    if(!matched){reason="OUTSIDE_ALLOWED_SCOPE";goto report;}
    if(strlen(target)>=sizeof(parent)){goto report;} strcpy(parent,target);slash=strrchr(parent,'/');if(!slash)goto report;*slash='\0';
    if(iu_policy_scope_inspect(rootfd,parent,uid,gid,NULL,NULL,NULL,0)!=0){reason="UNSAFE_DIRECTORY";goto report;}
    if(fixture){int n=snprintf(physical,sizeof(physical),"%s%s",root,target);if(n<0||(size_t)n>=sizeof(physical))goto report;}else{if(strlen(target)>=sizeof(physical))goto report;strcpy(physical,target);}
    if(iu_execution_plan_create_v1(physical,&plan)!=0){reason=plan.error_code==IU_EXECUTION_PLAN_ERROR_IDENTITY_CHANGED?"IDENTITY_MISMATCH":"UNSAFE_TARGET";goto report;}
    if(iu_policy_inspect_path_v1(physical,(uint32_t)strlen(physical),&facts)!=0 || facts.descriptor_device!=plan.device_number || facts.descriptor_inode!=plan.inode || iu_execution_plan_revalidate_v1(&plan)!=0){reason="IDENTITY_MISMATCH";goto report;}
    config.enabled=0;config.compatibility_status=IU_COMPAT_UNVERIFIED;
    (void)iu_policy_evaluate_v1(&config,&facts,&operational);
    config.enabled=1;config.compatibility_status=IU_COMPAT_SUPPORTED_AND_VERIFIED;
    (void)iu_policy_evaluate_v1(&config,&facts,&simulated);
    printf("P003 operational result: %s\nP003 simulated scope result: %s\n",iu_policy_outcome_name_v1(operational.outcome),iu_policy_outcome_name_v1(simulated.outcome));
    printf("Identity: device=%llu inode=%llu size=%llu sha256=",(unsigned long long)plan.device_number,(unsigned long long)plan.inode,(unsigned long long)plan.file_size);
    for(unsigned i=0;i<IU_EXECUTION_PLAN_SHA256_SIZE;i++)printf("%02x",plan.sha256[i]);
    printf("\nArchitecture: %u\nMach-O file type: %u\nSignature classification: %s\nP009 adapter: %s\nMissing prerequisites mask: 0x%x\n",plan.architecture,plan.macho_filetype,iu_ame_macho_state_name_v1(plan.macho_state),iu_ame_compatibility_name_v1(plan.adapter_compatibility),plan.missing_prerequisites);
    if(simulated.outcome==IU_POLICY_SKIP_NOT_TARGETED)reason="OUTSIDE_ALLOWED_SCOPE";
    else if(simulated.outcome==IU_POLICY_DENY_IDENTITY_MISMATCH)reason="IDENTITY_MISMATCH";
    else if(simulated.outcome!=IU_POLICY_ALLOW_ELIGIBLE)reason="UNSAFE_TARGET";
    else if(plan.architecture!=IU_ARCH_ARM64 || plan.macho_filetype!=2 || plan.signature_preparation==IU_EXECUTION_PREP_UNSUPPORTED_TARGET || plan.signature_preparation==IU_EXECUTION_PREP_INVALID_BINARY)reason="UNSUPPORTED_MACHO";
    else if(plan.signature_preparation==IU_EXECUTION_PREP_MISSING_SIGNATURE_COMMAND)reason="MISSING_SIGNATURE_COMMAND";
    else if(plan.signature_preparation==IU_EXECUTION_PREP_REQUIRES_REPAIR)reason="PREPARATION_NOT_IMPLEMENTED";
    else reason="HYPOTHETICALLY_ELIGIBLE";
report:
    printf("Preview: %s\nBackend: BACKEND_UNVERIFIED\nPreparation: NOT_IMPLEMENTED\nDevice runtime verified: false\nOperational authorization: false\n",reason);
    puts("Hypothetical matching assumes a verified backend only for simulation; installed build, live hooks, signature acceptance and launch are unverified.");
    return 0;
}
