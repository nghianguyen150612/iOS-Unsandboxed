#define _POSIX_C_SOURCE 200809L
#include "iu_artifact_provenance.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static void digest_hex(const uint8_t *d,char *out){static const char h[]="0123456789abcdef";for(unsigned i=0;i<32;i++){out[i*2]=h[d[i]>>4];out[i*2+1]=h[d[i]&15];}out[64]=0;}
static void document(char *out,size_t cap,const struct iu_execution_plan_v1 *p,const char *source,const char *anchor,const char *origin,const char *alg,const char *proof){char hex[65];digest_hex(p->sha256,hex);assert(snprintf(out,cap,"schema_version=1\nartifact_sha256=%s\nartifact_size=%llu\narchitecture=%u\nfiletype=%u\nsource=%s\npublisher=fixture-publisher\nbuild=fixture-build\nmanifest=fixture-manifest\nanchor=%s\norigin=%s\nalgorithm=%s\nproof=%s\n",hex,(unsigned long long)p->file_size,p->architecture,p->macho_filetype,source,anchor,origin,alg,proof)>0);}
static uint32_t verify(const char *doc,size_t n,const struct iu_execution_plan_v1 *p){struct iu_provenance_result_v1 r;assert(iu_provenance_verify_v1((const uint8_t *)doc,n,p,&r)==0);assert(r.abi_version==1 && r.struct_size==sizeof(r));return r.state;}
int main(int argc,char **argv){
    struct iu_execution_plan_v1 p, altered; struct iu_provenance_result_v1 r; char doc[4096],temp[4096],path[1024];
    assert(argc==2);assert(snprintf(path,sizeof(path),"%s/parseable",argv[1])>0);assert(iu_execution_plan_create_v1(path,&p)==0);
    assert(verify(NULL,0,&p)==IU_PROVENANCE_EVIDENCE_ABSENT);
    document(doc,sizeof(doc),&p,"local","fixture-anchor","unprotected","none","fixture-proof");assert(verify(doc,strlen(doc),&p)==IU_PROVENANCE_LOCAL_DECLARATION_ONLY);
    document(doc,sizeof(doc),&p,"manifest","fixture-anchor","unprotected","none","fixture-proof");assert(verify(doc,strlen(doc),&p)==IU_PROVENANCE_UNVERIFIED);
    document(doc,sizeof(doc),&p,"manifest","fixture-anchor","unprotected","fixture-v1","proof-unprotected");
#ifdef IU_PROVENANCE_TESTING
    assert(verify(doc,strlen(doc),&p)==IU_PROVENANCE_EVIDENCE_VERIFIED);
    document(temp,sizeof(temp),&p,"manifest","fixture-anchor","protected","fixture-v1","proof-protected");assert(verify(temp,strlen(temp),&p)==IU_PROVENANCE_PROTECTED_ARTIFACT_KNOWN);
    document(temp,sizeof(temp),&p,"manifest","unknown-anchor","unprotected","fixture-v1","proof-unprotected");assert(verify(temp,strlen(temp),&p)==IU_PROVENANCE_EVIDENCE_UNTRUSTED);
    document(temp,sizeof(temp),&p,"manifest","fixture-anchor","protected","fixture-v1","proof-unprotected");assert(verify(temp,strlen(temp),&p)==IU_PROVENANCE_EVIDENCE_UNTRUSTED);
    document(temp,sizeof(temp),&p,"manifest","fixture-anchor","unprotected","fixture-v1","tampered");assert(verify(temp,strlen(temp),&p)==IU_PROVENANCE_EVIDENCE_UNTRUSTED);
#else
    assert(verify(doc,strlen(doc),&p)==IU_PROVENANCE_EVIDENCE_MALFORMED);
#endif
    altered=p;altered.sha256[0]^=1;
#ifdef IU_PROVENANCE_TESTING
    assert(verify(doc,strlen(doc),&altered)==IU_PROVENANCE_EVIDENCE_IDENTITY_MISMATCH);
#else
    assert(verify(doc,strlen(doc),&altered)==IU_PROVENANCE_EVIDENCE_MALFORMED);
#endif
    document(doc,sizeof(doc),&p,"manifest","fixture-anchor","unprotected","none","fixture-proof");
    altered=p;altered.sha256[0]^=1;assert(verify(doc,strlen(doc),&altered)==IU_PROVENANCE_EVIDENCE_IDENTITY_MISMATCH);
    strcpy(temp,doc);temp[15]='2';assert(verify(temp,strlen(temp),&p)==IU_PROVENANCE_EVIDENCE_MALFORMED);
    strcpy(temp,doc);strcat(temp,"schema_version=1\n");assert(verify(temp,strlen(temp),&p)==IU_PROVENANCE_EVIDENCE_MALFORMED);
    assert(verify(doc,strlen(doc)-1,&p)==IU_PROVENANCE_EVIDENCE_MALFORMED);
    strcpy(temp,doc);temp[20]=(char)0xff;assert(verify(temp,strlen(doc),&p)==IU_PROVENANCE_EVIDENCE_MALFORMED);
    memset(temp,'x',sizeof(temp));temp[sizeof(temp)-1]='\n';assert(verify(temp,sizeof(temp),&p)==IU_PROVENANCE_EVIDENCE_MALFORMED);
    strcpy(temp,doc);strstr(temp,"artifact_sha256=")[16]='g';assert(verify(temp,strlen(temp),&p)==IU_PROVENANCE_EVIDENCE_MALFORMED);
    document(doc,sizeof(doc),&p,"manifest","fixture-anchor","unprotected","none","fixture-proof");
    for(size_t i=1;i<strlen(doc);i++) assert(verify(doc,i,&p)==IU_PROVENANCE_EVIDENCE_MALFORMED);
    for(size_t i=0;i<strlen(doc);i++) {strcpy(temp,doc);temp[i]='\0';assert(verify(temp,strlen(doc),&p)==IU_PROVENANCE_EVIDENCE_MALFORMED);}
    altered=p;altered.abi_version=2;assert(iu_provenance_verify_v1(NULL,0,&altered,&r)<0);
    assert(iu_provenance_verify_v1(NULL,1,&p,&r)<0);
    altered=p;altered.architecture=99;assert(iu_provenance_verify_v1(NULL,0,&altered,&r)<0);
    puts("provenance parser and trust boundary: PASS");return 0;
}
