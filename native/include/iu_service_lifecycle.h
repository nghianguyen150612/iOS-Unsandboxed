#ifndef IU_SERVICE_LIFECYCLE_H
#define IU_SERVICE_LIFECYCLE_H

#include <stddef.h>

enum iu_service_action {
    IU_SERVICE_PLAN = 0,
    IU_SERVICE_STATUS,
    IU_SERVICE_REGISTER,
    IU_SERVICE_START,
    IU_SERVICE_STOP,
    IU_SERVICE_UNREGISTER,
    IU_SERVICE_RECOVER
};

/* Project paths are fixed by the caller. root is / in production or a private
 * fixture root. The caller has already verified the P007 manifest and files. */
int iu_service_lifecycle_run(const char *root, int fixture,
                             enum iu_service_action action, int apply,
                             int confirmed, int acknowledge_run_at_load,
                             int installation_valid, int daemon_valid,
                             int template_valid);

#endif
