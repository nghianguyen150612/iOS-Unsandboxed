#define _POSIX_C_SOURCE 200809L
#include "iu_launch_binding.h"
#include <assert.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

int main(int argc, char **argv) {
    struct iu_launch_cli_summary_v2 summary;
    int fd;
    if (argc != 3) return 2;
    fd = open(argv[1], O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    assert(fd >= 0);

    memset(&summary, 0, sizeof(summary));
    summary.abi_version = IU_LAUNCH_BINDING_ABI_VERSION;
    summary.struct_size = sizeof(summary);
    assert(iu_launch_binding_preview_fd_summary_v2(fd, argv[1], &summary) < 0);

    memset(&summary, 0, sizeof(summary));
    summary.abi_version = IU_LAUNCH_SUMMARY_ABI_VERSION_V2;
    summary.struct_size = sizeof(summary) - sizeof(uint32_t);
    assert(iu_launch_binding_preview_fd_summary_v2(fd, argv[1], &summary) < 0);

    memset(&summary, 0, sizeof(summary));
    summary.abi_version = IU_LAUNCH_SUMMARY_ABI_VERSION_V2;
    summary.struct_size = sizeof(summary);
    assert(iu_launch_binding_preview_fd_summary_v2(fd, argv[1], &summary) == 0);
    assert(summary.abi_version == IU_LAUNCH_SUMMARY_ABI_VERSION_V2);
    assert(summary.struct_size == IU_LAUNCH_SUMMARY_V2_SIZE);
    assert(summary.artifact.abi_version == IU_EXECUTION_PLAN_ABI_VERSION);
    assert(summary.artifact.struct_size == IU_EXECUTION_PLAN_V1_SIZE);
    assert(summary.artifact.identity_status == IU_EXECUTION_IDENTITY_RECORDED);
    assert(summary.operational_authorization == 0);
    assert(summary.boundary_status == IU_LAUNCH_BOUNDARY_NOT_IMPLEMENTED);
    assert(iu_launch_binding_revalidate_fd_summary_v2(fd, &summary) == IU_LAUNCH_SAME_OPEN_OBJECT);
    assert(iu_launch_binding_revalidate_fd_summary_v2(fd, &summary) == IU_LAUNCH_SAME_OPEN_OBJECT);

    summary.scope_state = UINT32_MAX;
    assert(iu_launch_binding_revalidate_fd_summary_v2(fd, &summary) < 0);
    summary.scope_state = IU_LAUNCH_SCOPE_UNVERIFIED;
    summary.decision = UINT32_MAX;
    assert(iu_launch_binding_revalidate_fd_summary_v2(fd, &summary) < 0);
    summary.decision = IU_LAUNCH_POLICY_DISABLED;
    summary.operational_authorization = 1;
    assert(iu_launch_binding_revalidate_fd_summary_v2(fd, &summary) < 0);
    summary.operational_authorization = 0;
    summary.boundary_status = UINT32_MAX;
    assert(iu_launch_binding_revalidate_fd_summary_v2(fd, &summary) < 0);
    summary.boundary_status = IU_LAUNCH_BOUNDARY_NOT_IMPLEMENTED;

    assert(rename(argv[2], argv[1]) == 0);
    assert(iu_launch_binding_revalidate_fd_summary_v2(fd, &summary) == IU_LAUNCH_PATH_REPLACED);
    close(fd);
    puts("P013C descriptor summary v2 ABI, fail-closed enums, and revalidation: PASS");
    return 0;
}
