#include "iu_amethyst_adapter.h"
#include "iu_preflight.h"

#include <stdio.h>
#include <string.h>

int main(void)
{
    struct iu_ame_observed_facts_v1 facts;
    struct iu_ame_capability_result_v1 result;
    memset(&facts, 0, sizeof(facts));
    facts.abi_version = IU_AME_ADAPTER_ABI_VERSION;
    facts.struct_size = (uint32_t)sizeof(facts);
    facts.system_family = IU_SYSTEM_IOS;
    facts.architecture = IU_ARCH_ARM64;
    facts.reference_device_match = IU_MATCH_YES;
    facts.reference_os_match = IU_MATCH_YES;
    facts.component_present_mask = 3;
    facts.component_safe_mask = 3;
    facts.build_evidence = IU_AME_BUILD_TRUSTED_HASH_MATCH;
    facts.launchd_hook_evidence = IU_AME_HOOK_INDEPENDENTLY_VERIFIED;
    facts.base_hook_evidence = IU_AME_HOOK_INDEPENDENTLY_VERIFIED;
    facts.device_evidence_complete = 1;
    facts.source_revision.length = 40;
    memcpy(facts.source_revision.value, IU_AME_SOURCE_REVISION, 41);
    if (iu_ame_adapter_classify_v1(&facts, &result) != 0 ||
        result.compatibility == IU_AME_SUPPORTED_AND_VERIFIED) {
        fputs("production classifier promoted simulated evidence\n", stderr);
        return 1;
    }
    puts("production classifier remains fail-closed: PASS");
    return 0;
}
