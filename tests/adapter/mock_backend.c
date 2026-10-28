#include "mock_backend.h"

#include <string.h>

int32_t iu_test_mock_preview_v1(const struct iu_policy_config_v1 *config,
                                const struct iu_policy_target_v1 *target,
                                uint32_t capability_status,
                                struct iu_ame_preview_result_v1 *result)
{
    struct iu_policy_result_v1 policy;
    if (config == NULL || target == NULL || result == NULL) return -1;
    memset(result, 0, sizeof(*result));
    result->abi_version = IU_AME_ADAPTER_ABI_VERSION;
    result->struct_size = (uint32_t)sizeof(*result);
    result->adapter_compatibility = IU_AME_SUPPORTED_AND_VERIFIED; /* fixture assertion only */
    result->required_capability = IU_AME_CAP_ARM64_MACHO_INSPECTION;
    result->capability_status = capability_status;
    result->operational_authorization = 0;
    if (iu_policy_evaluate_v1(config, target, &policy) != 0) return -1;
    result->policy_outcome = policy.outcome;
    result->blocking_reason = policy.reason_code;
    result->preview_decision =
        policy.outcome == IU_POLICY_ALLOW_ELIGIBLE &&
        (capability_status == IU_AME_CAP_SOURCE_CONFIRMED ||
         capability_status == IU_AME_CAP_RUNTIME_VERIFIED)
            ? IU_AME_PREVIEW_HYPOTHETICALLY_ELIGIBLE
            : IU_AME_PREVIEW_BLOCKED;
    return 0;
}
