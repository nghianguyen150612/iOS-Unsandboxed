#include <stdio.h>
#include <string.h>

#include "iu_ipc_server.h"
#include "iu_preflight.h"
#include "iu_service_state.h"

#define IOS_UNSANDBOXED_VERSION "0.1.0"

enum exit_status {
    EXIT_OK = 0,
    EXIT_USAGE = 2,
    EXIT_NOT_IMPLEMENTED = 3,
    EXIT_PREFLIGHT_BLOCKED = 4,
    EXIT_INTERNAL = 5
};

static const char *const amethyst_component_paths[IU_PREFLIGHT_COMPONENT_COUNT] = {
    "/amethyst/launchd_hook.dylib",
    "/usr/lib/base_hook.dylib"
};

static void print_help(void)
{
    puts("Usage: ios-unsandboxedd [--help | --version | --probe | --serve | --test-socket <path> [--test-state <path>]]");
    puts("");
    puts("Diagnostic options:");
    puts("  -h, --help       Show this help");
    puts("  -V, --version    Show version");
    puts("      --probe      Run read-only compatibility diagnostics");
    puts("      --serve      Start production IPC server at /var/run/ios-unsandboxedd.sock (root only)");
    puts("      --test-socket <path>  Start isolated non-production test server");
    puts("      --test-state <path>   Read an isolated install-state fixture (test server only)");
    puts("");
    puts("IPC serves only read-only status and preflight requests; privileged operations remain unavailable.");
}

static void print_version(void)
{
    puts("ios-unsandboxedd " IOS_UNSANDBOXED_VERSION);
}

static const char *text_or_unknown(const struct iu_text_v1 *text)
{
    return text->length == 0 ? "UNKNOWN" : text->value;
}

static void print_component(const struct iu_preflight_result_v1 *result,
                            uint32_t index)
{
    uint32_t bit = UINT32_C(1) << index;
    const char *presence = (result->component_present_mask & bit) != 0 ? "present" : "missing";
    const char *type = (result->component_regular_mask & bit) != 0 ? "regular file" :
                       (result->component_present_mask & bit) != 0 ? "unexpected file type" :
                                                                    "not available";
    const char *readability = (result->component_readable_mask & bit) != 0 ? "readable" :
                                                                            "not readable";

    (void)printf("  %s: %s, %s, %s\n", amethyst_component_paths[index], presence, type,
                 readability);
    if ((result->component_present_mask & bit) != 0) {
        const struct iu_component_metadata_v1 *metadata = &result->components[index];
        (void)printf("    metadata: uid=%u gid=%u mode=%#o links=%u size=%llu bytes\n",
                     metadata->owner_uid, metadata->group_uid, metadata->mode,
                     metadata->link_count, (unsigned long long)metadata->size);
    }
}

static int print_probe(void)
{
    struct iu_preflight_result_v1 result;
    uint32_t present_project_paths = 0;
    uint32_t index;

    if (iu_preflight_detect_v1(&result) != 0) {
        (void)fprintf(stderr, "ios-unsandboxedd: preflight collection failed (%s).\n",
                      iu_preflight_error_name_v1(result.error_code));
        return EXIT_INTERNAL;
    }

    puts("iOS-Unsandboxed read-only preflight");
    (void)printf("Project version: %s\n", IOS_UNSANDBOXED_VERSION);
    (void)printf("Detected platform: %s\n",
                 iu_system_family_name_v1(result.system_family));
    (void)printf("Architecture: %s\n", iu_architecture_name_v1(result.architecture));
    (void)printf("Machine: %s\n", text_or_unknown(&result.machine));
    (void)printf("Product version: %s\n", text_or_unknown(&result.product_version));
    (void)printf("System build: %s\n", text_or_unknown(&result.system_build));
    (void)printf("Kernel release: %s\n", text_or_unknown(&result.kernel_release));

    if (result.rootful_layout_state == IU_ROOTFUL_PATHS_AVAILABLE) {
        puts("Rootful layout assessment: WARN — expected paths exist; rootful status is not proven");
    } else if (result.rootful_layout_state == IU_ROOTFUL_PATHS_MISSING) {
        puts("Rootful layout assessment: WARN — one or more rootful contract directories are missing");
    } else {
        puts("Rootful layout assessment: UNKNOWN — not an iOS target");
    }

    puts("Amethyst component detection:");
    for (index = 0; index < IU_PREFLIGHT_COMPONENT_COUNT; ++index) {
        print_component(&result, index);
    }

    (void)printf("Amethyst compatibility verification: %s (%s)\n",
                 iu_compatibility_status_name_v1(result.compatibility_status),
                 iu_preflight_error_name_v1(result.error_code));
    if (result.compatibility_status == IU_COMPAT_UNVERIFIED) {
        puts("  WARN — installed Amethyst build provenance and live hook state are not verified");
    }
    if (result.compatibility_status == IU_COMPAT_COMPONENT_MISSING) {
        puts("  FAIL — one or more expected Amethyst components are absent or unusable");
    }
    if (result.compatibility_status == IU_COMPAT_UNSUPPORTED_PLATFORM) {
        puts("  FAIL — this platform is outside the supported iPad mini 2 iOS target");
    }
    if (result.compatibility_status == IU_COMPAT_VERSION_MISMATCH) {
        puts("  FAIL — the detected iOS version does not match iOS 12.5.7");
    }

    for (index = 0; index < IU_PREFLIGHT_PROJECT_PATH_COUNT; ++index) {
        present_project_paths +=
            (result.project_path_present_mask & (UINT32_C(1) << index)) != 0 ? 1U : 0U;
    }
    (void)printf("Project rootful paths: %u/%u present (diagnostic metadata only)\n",
                 present_project_paths, IU_PREFLIGHT_PROJECT_PATH_COUNT);
    puts("Current preflight capability: read-only detection; activation eligibility is blocked");
    puts("Remaining requirements: verify installed Amethyst build, authenticated daemon policy,");
    puts("  hook initialization, and file identity through the final launch boundary.");
    puts("Device acceptance: NOT TESTED");
    puts("Diagnostic collection: PASS");

    return result.compatibility_status == IU_COMPAT_SUPPORTED_AND_VERIFIED ?
               EXIT_OK : EXIT_PREFLIGHT_BLOCKED;
}

int main(int argc, char **argv)
{
    if (argc == 2 && (strcmp(argv[1], "--help") == 0 || strcmp(argv[1], "-h") == 0)) {
        print_help();
        return EXIT_OK;
    }

    if (argc == 2 && (strcmp(argv[1], "--version") == 0 || strcmp(argv[1], "-V") == 0)) {
        print_version();
        return EXIT_OK;
    }

    if (argc == 2 && strcmp(argv[1], "--probe") == 0) {
        return print_probe();
    }

    if (argc == 2 && strcmp(argv[1], "--serve") == 0) {
        return iu_ipc_serve("/var/run/ios-unsandboxedd.sock", 0,
                            "/var/lib/ios-unsandboxed/install-state") == 0 ? EXIT_OK : EXIT_INTERNAL;
    }

    if (argc == 3 && strcmp(argv[1], "--test-socket") == 0) {
        return iu_ipc_serve(argv[2], 1, NULL) == 0 ? EXIT_OK : EXIT_INTERNAL;
    }

    if (argc == 5 && strcmp(argv[1], "--test-socket") == 0 &&
        strcmp(argv[3], "--test-state") == 0) {
        return iu_ipc_serve(argv[2], 1, argv[4]) == 0 ? EXIT_OK : EXIT_INTERNAL;
    }

    if (argc == 1) {
        (void)fprintf(stderr,
                      "ios-unsandboxedd: daemon service mode is not implemented; no service was started.\n");
        return EXIT_NOT_IMPLEMENTED;
    }

    if (argv[1][0] == '-') {
        (void)fprintf(stderr, "ios-unsandboxedd: unsupported option '%s'.\n", argv[1]);
        (void)fprintf(stderr, "Try 'ios-unsandboxedd --help' for usage.\n");
        return EXIT_USAGE;
    }

    (void)fprintf(stderr,
                  "ios-unsandboxedd: operation '%s' is not implemented; no service was started.\n",
                  argv[1]);
    return EXIT_NOT_IMPLEMENTED;
}
