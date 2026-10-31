#ifndef IU_TRUST_TRANSACTION_H
#define IU_TRUST_TRANSACTION_H
#include <stddef.h>
#include <stdint.h>

#define IU_TRUST_TRANSACTION_MAX_BYTES 512U
#define IU_TRUST_GENERATION_MAX_BYTES 192U
#define IU_TRUST_TRANSACTION_STAGE_NAME "stage.v1"

enum iu_trust_transaction_operation_v1 {
    IU_TRUST_TX_ADD = 1,
    IU_TRUST_TX_REVOKE = 2,
    IU_TRUST_TX_ROTATE = 3
};
enum iu_trust_transaction_phase_v1 {
    IU_TRUST_TX_PREPARED = 1,
    IU_TRUST_TX_COMMITTING = 2,
    IU_TRUST_TX_COMMITTED = 3
};
struct iu_trust_transaction_v1 {
    uint32_t schema_version;
    uint32_t operation;
    uint32_t phase;
    uint32_t old_store_present;
    uint64_t old_generation;
    uint64_t new_generation;
    char old_store_sha256[65];
    char new_store_sha256[65];
    char stage_name[16];
};
struct iu_trust_generation_v1 {
    uint64_t generation;
    char store_sha256[65];
};

/* Strict canonical ASCII journal codec; no filesystem access or authority. */
int32_t iu_trust_transaction_validate_v1(const struct iu_trust_transaction_v1 *tx);
int32_t iu_trust_transaction_parse_v1(const uint8_t *bytes, size_t length,
    struct iu_trust_transaction_v1 *out);
int32_t iu_trust_transaction_encode_v1(const struct iu_trust_transaction_v1 *tx,
    uint8_t *out, size_t capacity, size_t *length);
void iu_trust_sha256_hex_v1(const uint8_t *bytes, size_t length, char out[65]);
int32_t iu_trust_generation_validate_v1(const struct iu_trust_generation_v1 *generation);
int32_t iu_trust_generation_parse_v1(const uint8_t *bytes, size_t length,
    struct iu_trust_generation_v1 *out);
int32_t iu_trust_generation_encode_v1(const struct iu_trust_generation_v1 *generation,
    uint8_t *out, size_t capacity, size_t *length);
#endif
