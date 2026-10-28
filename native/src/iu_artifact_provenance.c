#include "iu_artifact_provenance.h"
#include <string.h>

static int hexval(unsigned char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    return -1;
}
static int number(const char *s, uint64_t *v) {
    uint64_t n = 0;
    if (!*s || (s[0] == '0' && s[1])) return 0;
    for (; *s; ++s) {
        unsigned d;
        if (*s < '0' || *s > '9') return 0;
        d = (unsigned)(*s - '0');
        if (n > (UINT64_MAX - d) / 10U) return 0;
        n = n * 10U + d;
    }
    *v = n; return 1;
}
static int token(const char *s, char *out) {
    size_t n = strlen(s);
    if (!n || n >= IU_PROVENANCE_TEXT_MAX) return 0;
    for (size_t i = 0; i < n; ++i) {
        unsigned char c = (unsigned char)s[i];
        if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
              (c >= '0' && c <= '9') || c == '.' || c == '_' || c == '-')) return 0;
    }
    memcpy(out, s, n + 1); return 1;
}
/* Ordered fields, canonical decimal/hex and ASCII deliberately avoid ambiguous
 * duplicate keys, encodings, and interpretation by a shell or JSON library. */
static uint32_t parse(const uint8_t *bytes, size_t length, struct iu_provenance_evidence_v1 *e) {
    static const char *const keys[] = {"schema_version", "artifact_sha256", "artifact_size", "architecture", "filetype", "source", "publisher", "build", "manifest", "anchor", "origin", "algorithm", "proof"};
    char buf[IU_PROVENANCE_EVIDENCE_MAX + 1U]; char *p; uint64_t v;
    if (!length || length > IU_PROVENANCE_EVIDENCE_MAX || bytes[length-1] != '\n') return IU_PROVENANCE_REASON_FORMAT;
    for (size_t i=0; i<length; ++i) if (bytes[i] != '\n' && (bytes[i] < 0x20 || bytes[i] > 0x7e)) return IU_PROVENANCE_REASON_FORMAT;
    memcpy(buf, bytes, length); buf[length] = '\0'; p=buf;
    memset(e,0,sizeof(*e)); e->abi_version=IU_ARTIFACT_PROVENANCE_ABI_VERSION; e->struct_size=(uint32_t)sizeof(*e);
    for (size_t i=0; i<sizeof(keys)/sizeof(keys[0]); ++i) {
        size_t k=strlen(keys[i]); char *end=strchr(p,'\n'); char *value;
        if (!end || (size_t)(end-p) <= k || memcmp(p,keys[i],k) || p[k]!='=') return IU_PROVENANCE_REASON_FORMAT;
        *end='\0'; value=p+k+1;
        switch(i) {
        case 0: if (!number(value,&v)) return IU_PROVENANCE_REASON_FORMAT; if(v!=1) return IU_PROVENANCE_REASON_SCHEMA; e->schema_version=1; break;
        case 1: if(strlen(value)!=64) return IU_PROVENANCE_REASON_FORMAT; for(size_t j=0;j<32;j++){int a=hexval((unsigned char)value[j*2]), b=hexval((unsigned char)value[j*2+1]);if(a<0||b<0)return IU_PROVENANCE_REASON_FORMAT;e->artifact_sha256[j]=(uint8_t)((a<<4)|b);} break;
        case 2: if(!number(value,&e->artifact_size))return IU_PROVENANCE_REASON_FORMAT; break;
        case 3: if(!number(value,&v)||v>UINT32_MAX)return IU_PROVENANCE_REASON_FORMAT; e->architecture=(uint32_t)v; if(e->architecture>IU_ARCH_X86)return IU_PROVENANCE_REASON_FORMAT; break;
        case 4: if(!number(value,&v)||v>UINT32_MAX)return IU_PROVENANCE_REASON_FORMAT; e->filetype=(uint32_t)v; break;
        case 5: if(!strcmp(value,"local"))e->source=IU_PROVENANCE_SOURCE_LOCAL;else if(!strcmp(value,"manifest"))e->source=IU_PROVENANCE_SOURCE_MANIFEST;else return IU_PROVENANCE_REASON_FORMAT; break;
        case 6: if(!token(value,e->publisher))return IU_PROVENANCE_REASON_FORMAT; break;
        case 7: if(!token(value,e->build))return IU_PROVENANCE_REASON_FORMAT; break;
        case 8: if(!token(value,e->manifest))return IU_PROVENANCE_REASON_FORMAT; break;
        case 9: if(!token(value,e->anchor))return IU_PROVENANCE_REASON_FORMAT; break;
        case 10: if(!strcmp(value,"unknown"))e->claimed_origin=IU_ORIGIN_UNKNOWN;else if(!strcmp(value,"protected"))e->claimed_origin=IU_ORIGIN_PROTECTED;else if(!strcmp(value,"unprotected"))e->claimed_origin=IU_ORIGIN_UNPROTECTED;else return IU_PROVENANCE_REASON_FORMAT; break;
        case 11: if(!token(value,e->algorithm))return IU_PROVENANCE_REASON_FORMAT; break;
        case 12: if(!token(value,e->proof))return IU_PROVENANCE_REASON_FORMAT; break;
        default: return IU_PROVENANCE_REASON_FORMAT;
        }
        p=end+1;
    }
    if (*p) return IU_PROVENANCE_REASON_FORMAT;
    if (strcmp(e->algorithm,"none") != 0) {
#ifdef IU_PROVENANCE_TESTING
        if (strcmp(e->algorithm,"fixture-v1") != 0) return IU_PROVENANCE_REASON_ALGORITHM;
#else
        return IU_PROVENANCE_REASON_ALGORITHM;
#endif
    }
    return IU_PROVENANCE_REASON_NONE;
}
int32_t iu_provenance_verify_v1(const uint8_t *bytes, size_t length, const struct iu_execution_plan_v1 *p, struct iu_provenance_result_v1 *r) {
    struct iu_provenance_evidence_v1 e; uint32_t reason, trust=IU_TRUST_UNAVAILABLE, origin=IU_ORIGIN_UNKNOWN;
    if (!r) return -1;
    memset(r,0,sizeof(*r)); r->abi_version=IU_ARTIFACT_PROVENANCE_ABI_VERSION; r->struct_size=(uint32_t)sizeof(*r);
    if (!p || p->abi_version!=IU_EXECUTION_PLAN_ABI_VERSION || p->struct_size!=sizeof(*p) ||
        p->identity_status!=IU_EXECUTION_IDENTITY_RECORDED || p->inspection_status!=IU_EXECUTION_INSPECTION_COMPLETE ||
        p->architecture>IU_ARCH_X86 || p->macho_state<IU_AME_MACHO_PARSEABLE_CODEDIRECTORY || p->macho_state>IU_AME_MACHO_IO_ERROR ||
        p->operational_authorization!=0 || (bytes==NULL && length!=0)) return -1;
    if (!length) {r->state=IU_PROVENANCE_EVIDENCE_ABSENT;r->reason=IU_PROVENANCE_REASON_ABSENT;return 0;}
    reason=parse(bytes,length,&e);
    if(reason){r->state=IU_PROVENANCE_EVIDENCE_MALFORMED;r->reason=reason;return 0;}
    r->source=e.source;
    if(e.artifact_size!=p->file_size || e.architecture!=p->architecture || e.filetype!=p->macho_filetype || memcmp(e.artifact_sha256,p->sha256,32)){
        r->state=IU_PROVENANCE_EVIDENCE_IDENTITY_MISMATCH;r->reason=IU_PROVENANCE_REASON_IDENTITY;return 0;
    }
    r->identity_match=1;
    if(e.source==IU_PROVENANCE_SOURCE_LOCAL){r->state=IU_PROVENANCE_LOCAL_DECLARATION_ONLY;r->reason=IU_PROVENANCE_REASON_LOCAL_DECLARATION;return 0;}
#ifdef IU_PROVENANCE_TESTING
    if(!strcmp(e.algorithm,"fixture-v1")) trust=iu_provenance_test_verify(&e,bytes,length,&origin);
#endif
    if(trust==IU_TRUST_REJECTED){r->state=IU_PROVENANCE_EVIDENCE_UNTRUSTED;r->reason=IU_PROVENANCE_REASON_UNTRUSTED_ANCHOR;return 0;}
    if(trust!=IU_TRUST_AUTHENTICATED || origin>IU_ORIGIN_UNPROTECTED){r->state=IU_PROVENANCE_UNVERIFIED;r->reason=IU_PROVENANCE_REASON_NO_VERIFIER;return 0;}
    r->document_integrity=1;r->publisher_authenticated=1;r->protected_classification=origin;
    if(origin==IU_ORIGIN_PROTECTED){r->state=IU_PROVENANCE_PROTECTED_ARTIFACT_KNOWN;r->reason=IU_PROVENANCE_REASON_PROTECTED;}
    else {r->state=IU_PROVENANCE_EVIDENCE_VERIFIED;r->reason=IU_PROVENANCE_REASON_AUTHENTICATED;}
    return 0;
}
const char *iu_provenance_state_name_v1(uint32_t state) {
    static const char *const names[]={"UNKNOWN","EVIDENCE_ABSENT","LOCAL_DECLARATION_ONLY","EVIDENCE_MALFORMED","EVIDENCE_IDENTITY_MISMATCH","EVIDENCE_UNTRUSTED","EVIDENCE_VERIFIED","PROTECTED_ARTIFACT_KNOWN","PROVENANCE_UNVERIFIED"};
    return state < sizeof(names)/sizeof(names[0]) ? names[state] : "INVALID";
}
