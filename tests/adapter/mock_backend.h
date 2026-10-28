#ifndef IU_TEST_MOCK_BACKEND_H
#define IU_TEST_MOCK_BACKEND_H

#include "iu_amethyst_adapter.h"

/* Test executable only. This has no production symbol or environment switch. */
int32_t iu_test_mock_preview_v1(const struct iu_policy_config_v1 *config,
                                const struct iu_policy_target_v1 *target,
                                uint32_t capability_status,
                                struct iu_ame_preview_result_v1 *result);

#endif
