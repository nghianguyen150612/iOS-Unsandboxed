#include "iu_trust_store.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void self_test(void) {
    struct iu_trust_store_v1 s; uint8_t out[IU_TRUST_STORE_MAX_BYTES];size_t n; char id[33];
    static const uint8_t key[32]={0xd7,0x5a,0x98,0x01,0x82,0xb1,0x0a,0xb7,0xd5,0x4b,0xfe,0xd3,0xc9,0x64,0x07,0x3a,0x0e,0xe1,0x72,0xf3,0xda,0xa6,0x23,0x25,0xaf,0x02,0x1a,0x68,0xf7,0x07,0x51,0x1a};
    memset(&s,0,sizeof(s));s.abi_version=1;s.struct_size=sizeof(s);s.generation=1;
    assert(iu_trust_store_validate_v1(&s)==0);
    assert(iu_trust_store_encode_v1(&s,out,2,&n)==IU_TRUST_CODEC_SPACE && n==0);
    assert(iu_trust_store_encode_v1(&s,out,sizeof(out),&n)==0);
    assert(iu_trust_store_parse_v1(out,n,&s)==0);
    assert(iu_trust_key_id_v1(key,id)==0 && !strcmp(id,"21fe31dfa154a261626bf854046fd227"));
    s.abi_version=2;assert(iu_trust_store_validate_v1(&s)==IU_TRUST_CODEC_ABI);
    assert(iu_trust_store_parse_v1(NULL,1,&s)==IU_TRUST_CODEC_ARGUMENT);
}
int main(int argc,char **argv) {
    uint8_t input[IU_TRUST_STORE_MAX_BYTES+1],output[IU_TRUST_STORE_MAX_BYTES];struct iu_trust_store_v1 store;size_t n,written;
    if(argc==2 && !strcmp(argv[1],"--self-test")){self_test();puts("trust codec C17 API: PASS");return 0;}
    if(argc!=1)return 2;
    n=fread(input,1,sizeof(input),stdin);if(ferror(stdin))return 2;
    if(iu_trust_store_parse_v1(input,n,&store)!=0)return 1;
    if(iu_trust_store_encode_v1(&store,output,sizeof(output),&written)!=0)return 2;
    return fwrite(output,1,written,stdout)==written?0:2;
}
