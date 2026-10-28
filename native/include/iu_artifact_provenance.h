#ifndef IU_ARTIFACT_PROVENANCE_H
#define IU_ARTIFACT_PROVENANCE_H
#include "iu_execution_planner.h"
#include <stddef.h>
#include <stdint.h>
#define IU_ARTIFACT_PROVENANCE_ABI_VERSION UINT32_C(1)
#define IU_PROVENANCE_EVIDENCE_MAX 2048U
#define IU_PROVENANCE_TEXT_MAX 96U
#define IU_PROVENANCE_EVIDENCE_V1_SIZE UINT32_C(648)
#define IU_PROVENANCE_RESULT_V1_SIZE UINT32_C(36)

enum iu_provenance_state_v1 {
    IU_PROVENANCE_UNKNOWN, IU_PROVENANCE_EVIDENCE_ABSENT,
    IU_PROVENANCE_LOCAL_DECLARATION_ONLY, IU_PROVENANCE_EVIDENCE_MALFORMED,
    IU_PROVENANCE_EVIDENCE_IDENTITY_MISMATCH, IU_PROVENANCE_EVIDENCE_UNTRUSTED,
    IU_PROVENANCE_EVIDENCE_VERIFIED, IU_PROVENANCE_PROTECTED_ARTIFACT_KNOWN,
    IU_PROVENANCE_UNVERIFIED
};
enum iu_provenance_source_v1 { IU_PROVENANCE_SOURCE_UNKNOWN, IU_PROVENANCE_SOURCE_LOCAL, IU_PROVENANCE_SOURCE_MANIFEST };
enum iu_provenance_reason_v1 { IU_PROVENANCE_REASON_NONE, IU_PROVENANCE_REASON_ABSENT,
    IU_PROVENANCE_REASON_FORMAT, IU_PROVENANCE_REASON_SCHEMA, IU_PROVENANCE_REASON_ALGORITHM,
    IU_PROVENANCE_REASON_IDENTITY, IU_PROVENANCE_REASON_LOCAL_DECLARATION,
    IU_PROVENANCE_REASON_NO_VERIFIER, IU_PROVENANCE_REASON_UNTRUSTED_ANCHOR,
    IU_PROVENANCE_REASON_AUTHENTICATED, IU_PROVENANCE_REASON_PROTECTED };
enum iu_provenance_trust_v1 { IU_TRUST_UNAVAILABLE, IU_TRUST_REJECTED, IU_TRUST_AUTHENTICATED };
enum iu_provenance_origin_v1 { IU_ORIGIN_UNKNOWN, IU_ORIGIN_PROTECTED, IU_ORIGIN_UNPROTECTED };
struct iu_provenance_evidence_v1 {
    uint32_t abi_version, struct_size, schema_version, source;
    uint8_t artifact_sha256[32];
    uint64_t artifact_size;
    uint32_t architecture, filetype, claimed_origin;
    char publisher[IU_PROVENANCE_TEXT_MAX], build[IU_PROVENANCE_TEXT_MAX];
    char manifest[IU_PROVENANCE_TEXT_MAX], anchor[IU_PROVENANCE_TEXT_MAX];
    char algorithm[IU_PROVENANCE_TEXT_MAX], proof[IU_PROVENANCE_TEXT_MAX];
};
struct iu_provenance_result_v1 {
    uint32_t abi_version, struct_size, state, reason, source;
    uint32_t identity_match, document_integrity, publisher_authenticated, protected_classification;
};
_Static_assert(sizeof(struct iu_provenance_evidence_v1)==IU_PROVENANCE_EVIDENCE_V1_SIZE, "provenance evidence ABI changed");
_Static_assert(sizeof(struct iu_provenance_result_v1)==IU_PROVENANCE_RESULT_V1_SIZE, "provenance result ABI changed");
/* Evidence is a bounded byte sequence, never executed or fetched. `plan` is a
 * descriptor-checked P010 snapshot; evidence itself is not an authorization. */
int32_t iu_provenance_verify_v1(const uint8_t *bytes, size_t length,
    const struct iu_execution_plan_v1 *plan, struct iu_provenance_result_v1 *result);
const char *iu_provenance_state_name_v1(uint32_t state);
#ifdef IU_PROVENANCE_TESTING
/* Only test binaries provide this symbol. Authentication and origin are
 * distinct results. Production has no runtime-selectable provider. */
uint32_t iu_provenance_test_verify(const struct iu_provenance_evidence_v1 *evidence,
                                    const uint8_t *document, size_t length, uint32_t *origin);
#endif
#endif
