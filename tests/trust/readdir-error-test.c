#define _DARWIN_C_SOURCE 1
#define _POSIX_C_SOURCE 200809L
#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static unsigned read_calls;
static struct dirent scripted_entry;

static struct dirent *scripted_readdir(DIR *stream)
{
    (void)stream;
    if (read_calls++ == 0U) {
        memset(&scripted_entry, 0, sizeof(scripted_entry));
        strcpy(scripted_entry.d_name, ".");
        return &scripted_entry;
    }
    errno = EIO;
    return NULL;
}

#define readdir scripted_readdir
#include "../../native/src/iu_trust_manager.c"
#undef readdir

int main(void)
{
    char path[] = "/tmp/iu-readdir-error-XXXXXX";
    unsigned mask = 0;
    int root = mkdtemp(path) != NULL ? open(path, O_RDONLY | O_DIRECTORY) : -1;
    int file;
    assert(root >= 0);
    file = openat(root, "unobserved-transaction-evidence", O_CREAT | O_EXCL | O_WRONLY, 0600);
    assert(file >= 0);
    assert(close(file) == 0);

    assert(scan_artifacts(root, &mask) != 0);

    assert(unlinkat(root, "unobserved-transaction-evidence", 0) == 0);
    assert(close(root) == 0);
    assert(rmdir(path) == 0);
    puts("Publisher trust directory scan fails closed on readdir errors");
    return 0;
}
