#include "iu_trust_transaction.h"
#include <stdio.h>
#include <string.h>

struct sha256_ctx { uint32_t h[8]; uint64_t bits; uint8_t block[64]; size_t used; };
static uint32_t rotr(uint32_t x,unsigned n){return (x>>n)|(x<<(32U-n));}
static uint32_t be32(const uint8_t *p){return ((uint32_t)p[0]<<24)|((uint32_t)p[1]<<16)|((uint32_t)p[2]<<8)|p[3];}
static void transform(struct sha256_ctx *c,const uint8_t *p){
 static const uint32_t k[64]={0x428a2f98U,0x71374491U,0xb5c0fbcfU,0xe9b5dba5U,0x3956c25bU,0x59f111f1U,0x923f82a4U,0xab1c5ed5U,0xd807aa98U,0x12835b01U,0x243185beU,0x550c7dc3U,0x72be5d74U,0x80deb1feU,0x9bdc06a7U,0xc19bf174U,0xe49b69c1U,0xefbe4786U,0x0fc19dc6U,0x240ca1ccU,0x2de92c6fU,0x4a7484aaU,0x5cb0a9dcU,0x76f988daU,0x983e5152U,0xa831c66dU,0xb00327c8U,0xbf597fc7U,0xc6e00bf3U,0xd5a79147U,0x06ca6351U,0x14292967U,0x27b70a85U,0x2e1b2138U,0x4d2c6dfcU,0x53380d13U,0x650a7354U,0x766a0abbU,0x81c2c92eU,0x92722c85U,0xa2bfe8a1U,0xa81a664bU,0xc24b8b70U,0xc76c51a3U,0xd192e819U,0xd6990624U,0xf40e3585U,0x106aa070U,0x19a4c116U,0x1e376c08U,0x2748774cU,0x34b0bcb5U,0x391c0cb3U,0x4ed8aa4aU,0x5b9cca4fU,0x682e6ff3U,0x748f82eeU,0x78a5636fU,0x84c87814U,0x8cc70208U,0x90befffaU,0xa4506cebU,0xbef9a3f7U,0xc67178f2U};
 uint32_t w[64],a,b,d,e,f,g,h,x;size_t i;for(i=0;i<16;i++)w[i]=be32(p+4*i);for(;i<64;i++){uint32_t s0=rotr(w[i-15],7)^rotr(w[i-15],18)^(w[i-15]>>3),s1=rotr(w[i-2],17)^rotr(w[i-2],19)^(w[i-2]>>10);w[i]=w[i-16]+s0+w[i-7]+s1;}a=c->h[0];b=c->h[1];x=c->h[2];d=c->h[3];e=c->h[4];f=c->h[5];g=c->h[6];h=c->h[7];
 for(i=0;i<64;i++){uint32_t s1=rotr(e,6)^rotr(e,11)^rotr(e,25),ch=(e&f)^(~e&g),t1=h+s1+ch+k[i]+w[i],s0=rotr(a,2)^rotr(a,13)^rotr(a,22),maj=(a&b)^(a&x)^(b&x),t2=s0+maj;h=g;g=f;f=e;e=d+t1;d=x;x=b;b=a;a=t1+t2;}c->h[0]+=a;c->h[1]+=b;c->h[2]+=x;c->h[3]+=d;c->h[4]+=e;c->h[5]+=f;c->h[6]+=g;c->h[7]+=h;
}
void iu_trust_sha256_hex_v1(const uint8_t *bytes,size_t length,char out[65]){
 static const uint32_t init[8]={0x6a09e667U,0xbb67ae85U,0x3c6ef372U,0xa54ff53aU,0x510e527fU,0x9b05688cU,0x1f83d9abU,0x5be0cd19U};static const char hex[]="0123456789abcdef";struct sha256_ctx c;size_t i;c.bits=0;c.used=0;memcpy(c.h,init,sizeof(init));while(length){size_t take=64U-c.used;if(take>length)take=length;memcpy(c.block+c.used,bytes,take);c.used+=take;c.bits+=(uint64_t)take*8U;bytes+=take;length-=take;if(c.used==64U){transform(&c,c.block);c.used=0;}}{uint64_t bits=c.bits;c.block[c.used++]=0x80;if(c.used>56){memset(c.block+c.used,0,64-c.used);transform(&c,c.block);c.used=0;}memset(c.block+c.used,0,56-c.used);for(i=0;i<8;i++)c.block[63-i]=(uint8_t)(bits>>(i*8));transform(&c,c.block);}for(i=0;i<8;i++){out[i*8]=hex[c.h[i]>>28];out[i*8+1]=hex[(c.h[i]>>24)&15];out[i*8+2]=hex[(c.h[i]>>20)&15];out[i*8+3]=hex[(c.h[i]>>16)&15];out[i*8+4]=hex[(c.h[i]>>12)&15];out[i*8+5]=hex[(c.h[i]>>8)&15];out[i*8+6]=hex[(c.h[i]>>4)&15];out[i*8+7]=hex[c.h[i]&15];}out[64]='\0';
}
static int hex64(const char *s){for(size_t i=0;i<64;i++)if(!((s[i]>='0'&&s[i]<='9')||(s[i]>='a'&&s[i]<='f')))return 0;return s[64]=='\0';}
static int parse_uint(const char *s,uint64_t *out){uint64_t n=0;if(!s||!*s||(s[0]=='0'&&s[1]))return -1;for(;*s;s++){unsigned v;if(*s<'0'||*s>'9')return -1;v=(unsigned)(*s-'0');if(n>(UINT64_MAX-v)/10U)return -1;n=n*10U+v;}*out=n;return 0;}
int32_t iu_trust_transaction_validate_v1(const struct iu_trust_transaction_v1 *tx){if(!tx||tx->schema_version!=1||tx->operation<IU_TRUST_TX_ADD||tx->operation>IU_TRUST_TX_ROTATE||tx->phase<IU_TRUST_TX_PREPARED||tx->phase>IU_TRUST_TX_COMMITTED||tx->new_generation==0||!memchr(tx->stage_name,'\0',sizeof(tx->stage_name))||strcmp(tx->stage_name,IU_TRUST_TRANSACTION_STAGE_NAME)||!hex64(tx->new_store_sha256))return -1;if(tx->old_store_present){if(tx->old_generation==0||tx->old_generation==UINT64_MAX||tx->new_generation!=tx->old_generation+1||!hex64(tx->old_store_sha256))return -1;}else if(tx->old_generation!=0||!memchr(tx->old_store_sha256,'\0',sizeof(tx->old_store_sha256))||strcmp(tx->old_store_sha256,"none")||tx->new_generation!=1||tx->operation!=IU_TRUST_TX_ADD)return -1;return 0;}
int32_t iu_trust_transaction_parse_v1(const uint8_t *bytes,size_t length,struct iu_trust_transaction_v1 *out){char copy[IU_TRUST_TRANSACTION_MAX_BYTES+1];char *lines[9],*p;size_t n=0;if(!bytes||!out||length==0||length>IU_TRUST_TRANSACTION_MAX_BYTES||bytes[length-1]!='\n'||memchr(bytes,0,length)||memchr(bytes,'\r',length))return -1;for(size_t i=0;i<length;i++)if(bytes[i]<0x20||bytes[i]>0x7e){if(bytes[i]!='\n')return -1;}memcpy(copy,bytes,length);copy[length]=0;p=copy;while(*p){char *end=strchr(p,'\n');if(!end||n>=9)return -1;*end=0;lines[n++]=p;p=end+1;}if(n!=9||strcmp(lines[0],"ios-unsandboxed-trust-transaction")||strcmp(lines[1],"schema_version=1"))return -1;memset(out,0,sizeof(*out));out->schema_version=1;
 const char *keys[7]={"operation=","old_generation=","new_generation=","old_store_sha256=","new_store_sha256=","stage_name=","phase="};char *vals[7];for(size_t i=0;i<7;i++){size_t k=strlen(keys[i]);if(strncmp(lines[i+2],keys[i],k)||!lines[i+2][k])return -1;vals[i]=lines[i+2]+k;}
 if(!strcmp(vals[0],"add"))out->operation=IU_TRUST_TX_ADD;else if(!strcmp(vals[0],"revoke"))out->operation=IU_TRUST_TX_REVOKE;else if(!strcmp(vals[0],"rotate"))out->operation=IU_TRUST_TX_ROTATE;else return -1;
 if(!strcmp(vals[1],"none")){out->old_store_present=0;out->old_generation=0;memcpy(out->old_store_sha256,"none",5);}else{out->old_store_present=1;if(parse_uint(vals[1],&out->old_generation))return -1;}
 if(parse_uint(vals[2],&out->new_generation))return -1;
 if(strlen(vals[3])>=sizeof(out->old_store_sha256)||strlen(vals[4])!=64||strlen(vals[5])>=sizeof(out->stage_name))return -1;
 strcpy(out->old_store_sha256,vals[3]);strcpy(out->new_store_sha256,vals[4]);strcpy(out->stage_name,vals[5]);
 if(!strcmp(vals[6],"prepared"))out->phase=IU_TRUST_TX_PREPARED;
 else if(!strcmp(vals[6],"committing"))out->phase=IU_TRUST_TX_COMMITTING;
 else if(!strcmp(vals[6],"committed"))out->phase=IU_TRUST_TX_COMMITTED;
 else return -1;
 return iu_trust_transaction_validate_v1(out);}
int32_t iu_trust_transaction_encode_v1(const struct iu_trust_transaction_v1 *tx,uint8_t *out,size_t capacity,size_t *length){char text[IU_TRUST_TRANSACTION_MAX_BYTES+1];const char *op,*phase;int n;if(!out||!length||iu_trust_transaction_validate_v1(tx))return -1;op=tx->operation==IU_TRUST_TX_ADD?"add":tx->operation==IU_TRUST_TX_REVOKE?"revoke":"rotate";phase=tx->phase==IU_TRUST_TX_PREPARED?"prepared":tx->phase==IU_TRUST_TX_COMMITTING?"committing":"committed";if(tx->old_store_present)n=snprintf(text,sizeof(text),"ios-unsandboxed-trust-transaction\nschema_version=1\noperation=%s\nold_generation=%llu\nnew_generation=%llu\nold_store_sha256=%s\nnew_store_sha256=%s\nstage_name=%s\nphase=%s\n",op,(unsigned long long)tx->old_generation,(unsigned long long)tx->new_generation,tx->old_store_sha256,tx->new_store_sha256,tx->stage_name,phase);else n=snprintf(text,sizeof(text),"ios-unsandboxed-trust-transaction\nschema_version=1\noperation=%s\nold_generation=none\nnew_generation=%llu\nold_store_sha256=none\nnew_store_sha256=%s\nstage_name=%s\nphase=%s\n",op,(unsigned long long)tx->new_generation,tx->new_store_sha256,tx->stage_name,phase);if(n<0||(size_t)n>=sizeof(text)||(size_t)n>capacity)return -1;memcpy(out,text,(size_t)n);*length=(size_t)n;return 0;}

int32_t iu_trust_generation_validate_v1(const struct iu_trust_generation_v1 *generation) {
    if(!generation||generation->generation==0||!hex64(generation->store_sha256))return -1;
    return 0;
}
int32_t iu_trust_generation_parse_v1(const uint8_t *bytes,size_t length,struct iu_trust_generation_v1 *out) {
    char copy[IU_TRUST_GENERATION_MAX_BYTES+1];char *lines[4],*p;size_t count=0;uint64_t value;
    if(!bytes||!out||length==0||length>IU_TRUST_GENERATION_MAX_BYTES||bytes[length-1]!='\n'||memchr(bytes,0,length)||memchr(bytes,'\r',length))return -1;
    for(size_t i=0;i<length;i++)if(bytes[i]<0x20||bytes[i]>0x7e){if(bytes[i]!='\n')return -1;}
    memcpy(copy,bytes,length);copy[length]=0;p=copy;
    while(*p){char *end=strchr(p,'\n');if(!end||count>=4)return -1;*end=0;lines[count++]=p;p=end+1;}
    if(count!=4||strcmp(lines[0],"ios-unsandboxed-trust-generation")||strcmp(lines[1],"schema_version=1")||strncmp(lines[2],"generation=",11)||strncmp(lines[3],"store_sha256=",13))return -1;
    if(parse_uint(lines[2]+11,&value)||strlen(lines[3]+13)!=64)return -1;
    memset(out,0,sizeof(*out));out->generation=value;strcpy(out->store_sha256,lines[3]+13);
    return iu_trust_generation_validate_v1(out);
}
int32_t iu_trust_generation_encode_v1(const struct iu_trust_generation_v1 *generation,uint8_t *out,size_t capacity,size_t *length) {
    char text[IU_TRUST_GENERATION_MAX_BYTES+1];int n;
    if(!out||!length||iu_trust_generation_validate_v1(generation))return -1;
    n=snprintf(text,sizeof(text),"ios-unsandboxed-trust-generation\nschema_version=1\ngeneration=%llu\nstore_sha256=%s\n",(unsigned long long)generation->generation,generation->store_sha256);
    if(n<0||(size_t)n>=sizeof(text)||(size_t)n>capacity)return -1;
    memcpy(out,text,(size_t)n);*length=(size_t)n;return 0;
}
