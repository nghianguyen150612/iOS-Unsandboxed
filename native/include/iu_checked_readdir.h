#ifndef IU_CHECKED_READDIR_H
#define IU_CHECKED_READDIR_H

#include <dirent.h>
#include <errno.h>

/* POSIX distinguishes end-of-directory from a read error through errno. */
static inline int iu_readdir_checked(DIR *stream, struct dirent **entry)
{
    if (stream == NULL || entry == NULL) {
        errno = EINVAL;
        return -1;
    }
    errno = 0;
    *entry = readdir(stream);
    if (*entry != NULL) return 1;
    return errno == 0 ? 0 : -1;
}

#endif
