#ifndef IU_BUILDER_TRANSACTION_H
#define IU_BUILDER_TRANSACTION_H
#include <stddef.h>
#include <stdint.h>

#define IU_BUILDER_TRANSACTION_MAX_BYTES 1024U
#define IU_BUILDER_TRANSACTION_ABI_V1 1U
enum iu_builder_operation_v1 { IU_BUILDER_ROOTS = 1, IU_BUILDER_POLICIES = 2, IU_BUILDER_COMBINED = 3 };
enum iu_builder_transaction_error_v1 { IU_BUILDER_OK = 0, IU_BUILDER_INVALID = -1, IU_BUILDER_BUFFER = -2 };
struct iu_builder_transaction_v1 {
    uint32_t schema_version, operation, old_roots_present, old_policies_present;
    uint64_t old_root_generation, new_root_generation, old_policy_generation, new_policy_generation;
    char old_root_sha256[65], new_root_sha256[65], old_policy_sha256[65], new_policy_sha256[65];
};
_Static_assert(sizeof(struct iu_builder_transaction_v1) == 312, "builder transaction ABI v1");
int32_t iu_builder_transaction_validate_v1(const struct iu_builder_transaction_v1 *tx);
int32_t iu_builder_transaction_parse_v1(const uint8_t *bytes, size_t length, struct iu_builder_transaction_v1 *out);
int32_t iu_builder_transaction_encode_v1(const struct iu_builder_transaction_v1 *tx, uint8_t *out, size_t capacity, size_t *length);
#endif
