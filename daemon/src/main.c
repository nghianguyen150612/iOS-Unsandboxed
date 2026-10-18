#include <stdio.h>
#include <string.h>

#define IOS_UNSANDBOXED_VERSION "0.1.0"

enum exit_status {
    EXIT_OK = 0,
    EXIT_USAGE = 2,
    EXIT_NOT_IMPLEMENTED = 3
};

static void print_help(void)
{
    puts("Usage: ios-unsandboxedd [--help | --version]");
    puts("");
    puts("Diagnostic options:");
    puts("  -h, --help       Show this help");
    puts("  -V, --version    Show version");
    puts("");
    puts("The daemon service mode is not implemented in v0.1.0.");
}

static void print_version(void)
{
    puts("ios-unsandboxedd " IOS_UNSANDBOXED_VERSION);
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
