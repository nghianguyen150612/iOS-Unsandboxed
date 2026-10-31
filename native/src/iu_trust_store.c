#include "iu_trust_store.h"
#include "iu_amethyst_adapter.h"
#include <inttypes.h>
#include <stdio.h>
#include <string.h>

static const char hexchars[]="0123456789abcdef";
static int hv(char c) { if(c>='0'&&c<='9')return c-'0'; if(c>='a'&&c<='f')return c-'a'+10; return -1; }
static int ident(const char *s,size_t cap) {
    size_t n=0;
    while(n<cap && s[n]) { unsigned char c=(unsigned char)s[n];
        if(!((c>='a'&&c<='z')||(c>='A'&&c<='Z')||(c>='0'&&c<='9')||c=='.'||c=='_'||c=='-'||c=='/'||c==':'||c=='+'||c=='@'))return 0;
        n++;
    }
    return n>0 && n<cap;
}
static int number(const char *s,uint64_t *out) {
    uint64_t v=0; if(!*s || (*s=='0'&&s[1]))return 0;
    while(*s){unsigned d;if(*s<'0'||*s>'9')return 0;d=(unsigned)(*s++-'0');if(v>(UINT64_MAX-d)/10U)return 0;v=v*10U+d;}*out=v;return 1;
}
int32_t iu_trust_key_id_v1(const uint8_t key[32],char id[IU_TRUST_KEY_ID_CAPACITY]) {
    uint8_t digest[32]; if(!key||!id)return IU_TRUST_CODEC_ARGUMENT;
    if(iu_ame_sha256_bytes_v1(key,32,digest)!=0)return IU_TRUST_CODEC_KEY;
    for(size_t i=0;i<16;i++){id[2*i]=hexchars[digest[i]>>4];id[2*i+1]=hexchars[digest[i]&15];}id[32]='\0';return 0;
}
int32_t iu_trust_record_validate_v1(const struct iu_trust_record_v1 *r) {
    char id[33]; if(!r)return IU_TRUST_CODEC_ARGUMENT;
    if(r->state!=IU_TRUST_KEY_ACTIVE && r->state!=IU_TRUST_KEY_REVOKED)return IU_TRUST_CODEC_FORMAT;
    if(r->reserved[0]||r->reserved[1]||!ident(r->publisher,sizeof(r->publisher)))return IU_TRUST_CODEC_FORMAT;
    if(iu_trust_key_id_v1(r->public_key,id)!=0 || memcmp(r->key_id,id,sizeof(id)))return IU_TRUST_CODEC_KEY;
    return 0;
}
int32_t iu_trust_store_validate_v1(const struct iu_trust_store_v1 *s) {
    int32_t rc; int n; size_t total; char line[512]; if(!s)return IU_TRUST_CODEC_ARGUMENT;
    if(s->abi_version!=IU_TRUST_STORE_ABI_VERSION || s->struct_size!=sizeof(*s))return IU_TRUST_CODEC_ABI;
    if(s->reserved || !s->generation)return IU_TRUST_CODEC_FORMAT;
    if(s->count>IU_TRUST_STORE_MAX_KEYS)return IU_TRUST_CODEC_LIMIT;
    n=snprintf(line,sizeof(line),"ios-unsandboxed-trust-store\nschema_version=1\ngeneration=%" PRIu64 "\nkey_count=%u\n",s->generation,s->count);
    if(n<0||(size_t)n>=sizeof(line))return IU_TRUST_CODEC_FORMAT;
    total=(size_t)n;
    for(uint32_t i=0;i<s->count;i++){
        const struct iu_trust_record_v1 *r=&s->keys[i];
        rc=iu_trust_record_validate_v1(r);if(rc)return rc;
        if(i && strcmp(s->keys[i-1].key_id,r->key_id)>=0)return IU_TRUST_CODEC_ORDER;
        n=snprintf(line,sizeof(line),"key_%u=%s|ed25519|%064d|publisher|%s|%s\n",i,r->key_id,0,r->publisher,r->state==IU_TRUST_KEY_ACTIVE?"active":"revoked");
        if(n<0||(size_t)n>=sizeof(line))return IU_TRUST_CODEC_FORMAT;
        total+=(size_t)n;
        if(total>IU_TRUST_STORE_MAX_BYTES)return IU_TRUST_CODEC_LIMIT;
    }
    return 0;
}
static int append(uint8_t *out,size_t cap,size_t *pos,const char *text) {
    size_t n=strlen(text);if(*pos>cap||n>cap-*pos)return 0;memcpy(out+*pos,text,n);*pos+=n;return 1;
}
int32_t iu_trust_store_encode_v1(const struct iu_trust_store_v1 *s,uint8_t *out,size_t capacity,size_t *length) {
    char line[512],pub[65];size_t pos=0;int n;int32_t rc;
    if(!out||!length)return IU_TRUST_CODEC_ARGUMENT;
    *length=0;
    rc=iu_trust_store_validate_v1(s);if(rc)return rc;
    n=snprintf(line,sizeof(line),"ios-unsandboxed-trust-store\nschema_version=1\ngeneration=%" PRIu64 "\nkey_count=%u\n",s->generation,s->count);
    if(n<0||(size_t)n>=sizeof(line)||!append(out,capacity,&pos,line))return IU_TRUST_CODEC_SPACE;
    for(uint32_t i=0;i<s->count;i++) {const struct iu_trust_record_v1 *r=&s->keys[i];
        for(size_t j=0;j<32;j++){pub[2*j]=hexchars[r->public_key[j]>>4];pub[2*j+1]=hexchars[r->public_key[j]&15];}pub[64]=0;
        n=snprintf(line,sizeof(line),"key_%u=%s|ed25519|%s|publisher|%s|%s\n",i,r->key_id,pub,r->publisher,r->state==IU_TRUST_KEY_ACTIVE?"active":"revoked");
        if(n<0||(size_t)n>=sizeof(line)||!append(out,capacity,&pos,line))return IU_TRUST_CODEC_SPACE;
        if(pos>IU_TRUST_STORE_MAX_BYTES)return IU_TRUST_CODEC_LIMIT;
    }
    if(pos>IU_TRUST_STORE_MAX_BYTES)return IU_TRUST_CODEC_LIMIT;
    *length=pos;return 0;
}
static char *nextline(char **p) { char *s=*p,*e=strchr(s,'\n');if(!e)return NULL;*e='\0';*p=e+1;return s; }
static char *field(char **p,char sep) {char *s=*p,*e=strchr(s,sep);if(!e)return NULL;*e='\0';*p=e+1;return s;}
int32_t iu_trust_store_parse_v1(const uint8_t *bytes,size_t length,struct iu_trust_store_v1 *out) {
    char buf[IU_TRUST_STORE_MAX_BYTES+1],canonical[IU_TRUST_STORE_MAX_BYTES],*p,*line,*part;uint64_t v;size_t encoded;int32_t rc;
    if(!out || (!bytes&&length))return IU_TRUST_CODEC_ARGUMENT;
    memset(out,0,sizeof(*out));
    if(!length || length>IU_TRUST_STORE_MAX_BYTES)return IU_TRUST_CODEC_LIMIT;
    if(bytes[length-1]!='\n')return IU_TRUST_CODEC_FORMAT;
    for(size_t i=0;i<length;i++)if(bytes[i]!='\n'&&(bytes[i]<0x20||bytes[i]>0x7e))return IU_TRUST_CODEC_FORMAT;
    memcpy(buf,bytes,length);buf[length]=0;p=buf;
    line=nextline(&p);if(!line||strcmp(line,"ios-unsandboxed-trust-store"))return IU_TRUST_CODEC_FORMAT;
    line=nextline(&p);if(!line||strcmp(line,"schema_version=1"))return IU_TRUST_CODEC_SCHEMA;
    line=nextline(&p);if(!line||strncmp(line,"generation=",11)||!number(line+11,&v)||!v)return IU_TRUST_CODEC_FORMAT;
    out->abi_version=1;out->struct_size=sizeof(*out);out->generation=v;
    line=nextline(&p);if(!line||strncmp(line,"key_count=",10)||!number(line+10,&v))return IU_TRUST_CODEC_FORMAT;
    if(v>IU_TRUST_STORE_MAX_KEYS)return IU_TRUST_CODEC_LIMIT;
    out->count=(uint32_t)v;
    for(uint32_t i=0;i<out->count;i++) {char prefix[20],*id,*alg,*key,*scope,*publisher;struct iu_trust_record_v1 *r=&out->keys[i];
        line=nextline(&p);if(!line)return IU_TRUST_CODEC_FORMAT;
        if(snprintf(prefix,sizeof(prefix),"key_%u=",i)<0||strncmp(line,prefix,strlen(prefix)))return IU_TRUST_CODEC_FORMAT;
        part=line+strlen(prefix);id=field(&part,'|');alg=field(&part,'|');key=field(&part,'|');scope=field(&part,'|');publisher=field(&part,'|');
        if(!id||!alg||!key||!scope||!publisher||strlen(id)!=32||strlen(key)!=64||strlen(publisher)>=sizeof(r->publisher)||strcmp(alg,"ed25519")||strcmp(scope,"publisher"))return IU_TRUST_CODEC_FORMAT;
        memcpy(r->key_id,id,33);memcpy(r->publisher,publisher,strlen(publisher)+1);
        for(size_t j=0;j<32;j++){int a=hv(key[2*j]),b=hv(key[2*j+1]);if(a<0||b<0)return IU_TRUST_CODEC_KEY;r->public_key[j]=(uint8_t)((a<<4)|b);}
        if(!strcmp(part,"active"))r->state=IU_TRUST_KEY_ACTIVE;else if(!strcmp(part,"revoked"))r->state=IU_TRUST_KEY_REVOKED;else return IU_TRUST_CODEC_FORMAT;
    }
    if(*p)return IU_TRUST_CODEC_FORMAT;
    rc=iu_trust_store_encode_v1(out,(uint8_t *)canonical,sizeof(canonical),&encoded);if(rc)return rc;
    if(encoded!=length||memcmp(canonical,bytes,length))return IU_TRUST_CODEC_FORMAT;
    return 0;
}
