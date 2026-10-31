#include "iu_builder_transaction.h"
#include <stdio.h>
#include <string.h>

static int hash_valid(const char value[65]) {
    for (size_t i = 0; i < 64; i++) if (!((value[i] >= '0' && value[i] <= '9') || (value[i] >= 'a' && value[i] <= 'f'))) return 0;
    return value[64] == '\0';
}
static int number(const char *s, uint64_t *out) {
    uint64_t value = 0;
    if (!*s || (s[0] == '0' && s[1])) return -1;
    for (; *s; s++) {
        unsigned digit;
        if (*s < '0' || *s > '9') return -1;
        digit = (unsigned)(*s - '0');
        if (value > (UINT64_MAX - digit) / 10U) return -1;
        value = value * 10U + digit;
    }
    *out = value;
    return 0;
}
static int transition(uint32_t present, uint64_t old_gen, uint64_t new_gen, const char *old_hash, const char *new_hash) {
    if (present > 1 || !hash_valid(new_hash)) return -1;
    if (!present) return old_gen == 0 && strcmp(old_hash, "none") == 0 && new_gen == 1 ? 1 : -1;
    if (!hash_valid(old_hash)) return -1;
    if (old_gen == new_gen && strcmp(old_hash, new_hash) == 0) return 0;
    return old_gen != UINT64_MAX && new_gen == old_gen + 1 && strcmp(old_hash, new_hash) != 0 ? 1 : -1;
}
int32_t iu_builder_transaction_validate_v1(const struct iu_builder_transaction_v1 *tx) {
    int roots, policies;
    if (!tx || tx->schema_version != 1 || !memchr(tx->old_root_sha256, 0, 65) || !memchr(tx->old_policy_sha256, 0, 65)) return IU_BUILDER_INVALID;
    roots = transition(tx->old_roots_present, tx->old_root_generation, tx->new_root_generation, tx->old_root_sha256, tx->new_root_sha256);
    policies = transition(tx->old_policies_present, tx->old_policy_generation, tx->new_policy_generation, tx->old_policy_sha256, tx->new_policy_sha256);
    if ((tx->operation == IU_BUILDER_ROOTS && roots == 1 && policies == 0) ||
        (tx->operation == IU_BUILDER_POLICIES && roots == 0 && policies == 1) ||
        (tx->operation == IU_BUILDER_COMBINED && roots == 1 && policies == 1)) return IU_BUILDER_OK;
    return IU_BUILDER_INVALID;
}
int32_t iu_builder_transaction_parse_v1(const uint8_t *bytes, size_t length, struct iu_builder_transaction_v1 *out) {
    char copy[IU_BUILDER_TRANSACTION_MAX_BYTES + 1], *lines[14], *p;
    const char *keys[] = {"operation=", "old_root_generation=", "new_root_generation=", "old_root_sha256=", "new_root_sha256=", "old_policy_generation=", "new_policy_generation=", "old_policy_sha256=", "new_policy_sha256="};
    char *v[9]; size_t count = 0;
    if (!bytes || !out || !length || length > IU_BUILDER_TRANSACTION_MAX_BYTES || bytes[length-1] != '\n') return IU_BUILDER_INVALID;
    for (size_t i = 0; i < length; i++) if (bytes[i] != '\n' && (bytes[i] < 0x20 || bytes[i] > 0x7e)) return IU_BUILDER_INVALID;
    memcpy(copy, bytes, length); copy[length] = 0; p = copy;
    while (*p) { char *end = strchr(p, '\n'); if (!end || count == 14) return IU_BUILDER_INVALID; *end = 0; lines[count++] = p; p = end + 1; }
    if (count != 14 || strcmp(lines[0], "ios-unsandboxed-builder-transaction") || strcmp(lines[1], "schema_version=1") || strcmp(lines[11], "stage_roots=roots.stage.v1") || strcmp(lines[12], "stage_policies=policies.stage.v1") || strcmp(lines[13], "phase=prepared")) return IU_BUILDER_INVALID;
    for (size_t i = 0; i < 9; i++) { size_t n = strlen(keys[i]); if (strncmp(lines[i+2], keys[i], n) || !lines[i+2][n]) return IU_BUILDER_INVALID; v[i] = lines[i+2]+n; }
    memset(out, 0, sizeof(*out)); out->schema_version = 1;
    if (!strcmp(v[0], "roots")) out->operation = IU_BUILDER_ROOTS; else if (!strcmp(v[0], "policies")) out->operation = IU_BUILDER_POLICIES; else if (!strcmp(v[0], "combined")) out->operation = IU_BUILDER_COMBINED; else return IU_BUILDER_INVALID;
    out->old_roots_present = strcmp(v[1], "none") != 0;
    out->old_policies_present = strcmp(v[5], "none") != 0;
    if ((out->old_roots_present && number(v[1], &out->old_root_generation)) || number(v[2], &out->new_root_generation) || (out->old_policies_present && number(v[5], &out->old_policy_generation)) || number(v[6], &out->new_policy_generation)) return IU_BUILDER_INVALID;
    if (strlen(v[3]) >= 65 || strlen(v[4]) != 64 || strlen(v[7]) >= 65 || strlen(v[8]) != 64) return IU_BUILDER_INVALID;
    strcpy(out->old_root_sha256, v[3]); strcpy(out->new_root_sha256, v[4]); strcpy(out->old_policy_sha256, v[7]); strcpy(out->new_policy_sha256, v[8]);
    return iu_builder_transaction_validate_v1(out);
}
int32_t iu_builder_transaction_encode_v1(const struct iu_builder_transaction_v1 *tx, uint8_t *out, size_t capacity, size_t *length) {
    char buffer[IU_BUILDER_TRANSACTION_MAX_BYTES+1], old_root[32], old_policy[32]; int n;
    const char *operation;
    if (!out || !length || iu_builder_transaction_validate_v1(tx)) return IU_BUILDER_INVALID;
    operation = tx->operation == IU_BUILDER_ROOTS ? "roots" : tx->operation == IU_BUILDER_POLICIES ? "policies" : "combined";
    if (tx->old_roots_present) (void)snprintf(old_root, sizeof(old_root), "%llu", (unsigned long long)tx->old_root_generation); else strcpy(old_root, "none");
    if (tx->old_policies_present) (void)snprintf(old_policy, sizeof(old_policy), "%llu", (unsigned long long)tx->old_policy_generation); else strcpy(old_policy, "none");
    n = snprintf(buffer, sizeof(buffer), "ios-unsandboxed-builder-transaction\nschema_version=1\noperation=%s\nold_root_generation=%s\nnew_root_generation=%llu\nold_root_sha256=%s\nnew_root_sha256=%s\nold_policy_generation=%s\nnew_policy_generation=%llu\nold_policy_sha256=%s\nnew_policy_sha256=%s\nstage_roots=roots.stage.v1\nstage_policies=policies.stage.v1\nphase=prepared\n", operation, old_root, (unsigned long long)tx->new_root_generation, tx->old_root_sha256, tx->new_root_sha256, old_policy, (unsigned long long)tx->new_policy_generation, tx->old_policy_sha256, tx->new_policy_sha256);
    if (n < 0 || (size_t)n >= sizeof(buffer) || (size_t)n > capacity) return IU_BUILDER_BUFFER;
    memcpy(out, buffer, (size_t)n); *length = (size_t)n; return IU_BUILDER_OK;
}
