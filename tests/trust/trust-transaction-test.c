#include "iu_trust_transaction.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

static void fill_hex(char out[65],char value){memset(out,value,64);out[64]='\0';}
int main(void){
    struct iu_trust_transaction_v1 tx={0},parsed;struct iu_trust_generation_v1 generation={0},generation_parsed;uint8_t bytes[IU_TRUST_TRANSACTION_MAX_BYTES];uint8_t generation_bytes[IU_TRUST_GENERATION_MAX_BYTES];size_t n=0,gn=0;char digest[65];
    tx.schema_version=1;tx.operation=IU_TRUST_TX_ADD;tx.phase=IU_TRUST_TX_PREPARED;tx.new_generation=1;
    strcpy(tx.old_store_sha256,"none");fill_hex(tx.new_store_sha256,'a');strcpy(tx.stage_name,IU_TRUST_TRANSACTION_STAGE_NAME);
    assert(iu_trust_transaction_validate_v1(&tx)==0);
    assert(iu_trust_transaction_encode_v1(&tx,bytes,sizeof(bytes),&n)==0);
    assert(iu_trust_transaction_parse_v1(bytes,n,&parsed)==0);
    assert(parsed.old_store_present==0&&parsed.old_generation==0&&parsed.new_generation==1);
    assert(parsed.operation==IU_TRUST_TX_ADD&&parsed.phase==IU_TRUST_TX_PREPARED);
    assert(iu_trust_transaction_encode_v1(&parsed,bytes,sizeof(bytes),&n)==0);
    assert(iu_trust_transaction_parse_v1(bytes,n,&tx)==0);
    generation.generation=1;fill_hex(generation.store_sha256,'b');
    assert(iu_trust_generation_encode_v1(&generation,generation_bytes,sizeof(generation_bytes),&gn)==0);
    assert(iu_trust_generation_parse_v1(generation_bytes,gn,&generation_parsed)==0);
    assert(generation_parsed.generation==1&&!strcmp(generation.store_sha256,generation_parsed.store_sha256));
    assert(iu_trust_generation_parse_v1(generation_bytes,gn-1,&generation_parsed)!=0);
    generation_parsed.generation=0;fill_hex(generation_parsed.store_sha256,'a');
    assert(iu_trust_generation_validate_v1(&generation_parsed)!=0);
    iu_trust_sha256_hex_v1((const uint8_t *)"abc",3,digest);
    assert(!strcmp(digest,"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"));
    {
        static const char unsupported[]="ios-unsandboxed-trust-transaction\nschema_version=2\n";
        assert(iu_trust_transaction_parse_v1((const uint8_t *)unsupported,sizeof(unsupported)-1,&parsed)!=0);
    }
    assert(iu_trust_transaction_parse_v1(bytes,n-1,&parsed)!=0);
    {
        static const char upper[]="ios-unsandboxed-trust-transaction\nschema_version=1\noperation=add\nold_generation=none\nnew_generation=1\nold_store_sha256=none\nnew_store_sha256=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\nstage_name=stage.v1\nphase=prepared\n";
        assert(iu_trust_transaction_parse_v1((const uint8_t *)upper,sizeof(upper)-1,&parsed)!=0);
    }
    {
        static const char reordered[]="ios-unsandboxed-trust-transaction\nschema_version=1\noperation=add\nnew_generation=1\nold_generation=none\nold_store_sha256=none\nnew_store_sha256=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\nstage_name=stage.v1\nphase=prepared\n";
        assert(iu_trust_transaction_parse_v1((const uint8_t *)reordered,sizeof(reordered)-1,&parsed)!=0);
    }
    strcpy(tx.old_store_sha256,"none");tx.old_store_present=1;tx.old_generation=UINT64_MAX;tx.new_generation=0;
    assert(iu_trust_transaction_validate_v1(&tx)!=0);
    tx.old_generation=9;tx.new_generation=9;fill_hex(tx.old_store_sha256,'b');
    assert(iu_trust_transaction_validate_v1(&tx)!=0);
    strcpy(tx.stage_name,"../store.v1");tx.old_store_present=0;tx.old_generation=0;tx.new_generation=1;strcpy(tx.old_store_sha256,"none");
    assert(iu_trust_transaction_validate_v1(&tx)!=0);
    puts("strict trust transaction codec and SHA-256 vectors: PASS");
    return 0;
}
