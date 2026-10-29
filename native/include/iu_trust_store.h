#ifndef IU_TRUST_STORE_H
#define IU_TRUST_STORE_H
#include <stddef.h>
#include <stdint.h>
#define IU_TRUST_STORE_ABI_VERSION UINT32_C(1)
#define IU_TRUST_STORE_MAX_KEYS 64U
#define IU_TRUST_STORE_MAX_BYTES 16384U
#define IU_TRUST_PUBLISHER_CAPACITY 193U
#define IU_TRUST_KEY_ID_CAPACITY 33U
#define IU_TRUST_RECORD_V1_SIZE 264U
#define IU_TRUST_STORE_V1_SIZE 16920U

enum iu_trust_codec_error_v1 { IU_TRUST_CODEC_OK=0, IU_TRUST_CODEC_ARGUMENT=-1,
    IU_TRUST_CODEC_ABI=-2, IU_TRUST_CODEC_FORMAT=-3, IU_TRUST_CODEC_SCHEMA=-4,
    IU_TRUST_CODEC_LIMIT=-5, IU_TRUST_CODEC_KEY=-6, IU_TRUST_CODEC_ORDER=-7,
    IU_TRUST_CODEC_SPACE=-8 };
enum iu_trust_key_state_v1 { IU_TRUST_KEY_ACTIVE=1, IU_TRUST_KEY_REVOKED=2 };
struct iu_trust_record_v1 {
    uint32_t state;
    uint8_t public_key[32];
    char key_id[IU_TRUST_KEY_ID_CAPACITY];
    char publisher[IU_TRUST_PUBLISHER_CAPACITY];
    uint8_t reserved[2];
};
struct iu_trust_store_v1 {
    uint32_t abi_version, struct_size, count, reserved;
    uint64_t generation;
    struct iu_trust_record_v1 keys[IU_TRUST_STORE_MAX_KEYS];
};
_Static_assert(sizeof(struct iu_trust_record_v1)==IU_TRUST_RECORD_V1_SIZE,"trust record ABI");
_Static_assert(sizeof(struct iu_trust_store_v1)==IU_TRUST_STORE_V1_SIZE,"trust store ABI");
/* No I/O and no trust or execution authorization. Public keys are checked as
 * 32-byte Ed25519 encodings; curve point validity is checked by the verifier. */
int32_t iu_trust_key_id_v1(const uint8_t key[32], char id[IU_TRUST_KEY_ID_CAPACITY]);
int32_t iu_trust_record_validate_v1(const struct iu_trust_record_v1 *record);
int32_t iu_trust_store_validate_v1(const struct iu_trust_store_v1 *store);
int32_t iu_trust_store_parse_v1(const uint8_t *bytes,size_t length,struct iu_trust_store_v1 *out);
int32_t iu_trust_store_encode_v1(const struct iu_trust_store_v1 *store,uint8_t *out,size_t capacity,size_t *length);
#endif
