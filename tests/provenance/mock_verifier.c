#include "iu_artifact_provenance.h"
#include <string.h>
/* Deterministic fake provider for test objects only; no key or production trust
 * claim. All assertion fields are checked, including the exact fixture digest. */
uint32_t iu_provenance_test_verify(const struct iu_provenance_evidence_v1 *e, const uint8_t *doc, size_t length, uint32_t *origin) {
    static const uint8_t digest[32] = { 0xbe,0xbd,0x20,0x56,0x4a,0x64,0xf4,0x7c,0x92,0xe2,0xd2,0xe5,0x4f,0x1a,0x14,0x09,0xeb,0x7f,0x98,0x11,0x10,0x17,0x8e,0xf1,0xa0,0x19,0x40,0xf9,0x92,0x7c,0xab,0x7d };
    (void)doc;(void)length;
    if(strcmp(e->anchor,"fixture-anchor"))return IU_TRUST_REJECTED;
    if(strcmp(e->publisher,"fixture-publisher") || strcmp(e->build,"fixture-build") || strcmp(e->manifest,"fixture-manifest") || strcmp(e->proof,"fixture-proof") || e->artifact_size!=140 || e->architecture!=1 || e->filetype!=2 || memcmp(e->artifact_sha256,digest,32))return IU_TRUST_REJECTED;
    *origin=e->claimed_origin;
    return IU_TRUST_AUTHENTICATED;
}
