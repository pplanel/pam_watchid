/*
 * test/harness.m — Standalone test runner for pam_watchid.so
 *
 * Dynamically loads the built module and triggers a PAM authentication transaction
 * without requiring changes to system files in /etc/pam.d/.
 */

#import <Foundation/Foundation.h>
#include <security/pam_appl.h>
#include <dlfcn.h>
#include <stdio.h>
#include <unistd.h>

static int dummy_conv(int num_msg, const struct pam_message **msg,
                      struct pam_response **resp, void *appdata_ptr) {
    (void)num_msg;
    (void)msg;
    (void)resp;
    (void)appdata_ptr;
    return PAM_SUCCESS;
}

int main(int argc, const char **argv) {
    @autoreleasepool {
        const char *module_path = "build/pam_watchid.so";
        void *handle = dlopen(module_path, RTLD_NOW | RTLD_GLOBAL);
        if (!handle) {
            fprintf(stderr, "dlopen failed for '%s': %s\n", module_path, dlerror());
            return 1;
        }

        typedef int (*pam_sm_auth_fn)(pam_handle_t *, int, int, const char **);
        pam_sm_auth_fn auth_fn = (pam_sm_auth_fn)dlsym(handle, "pam_sm_authenticate");
        if (!auth_fn) {
            fprintf(stderr, "dlsym failed for 'pam_sm_authenticate': %s\n", dlerror());
            dlclose(handle);
            return 1;
        }

        const char *user = getlogin();
        if (!user) user = getenv("USER");
        printf("Initiating PAM authentication test for user '%s'...\n", user);

        void *pam_lib = dlopen("/usr/lib/libpam.2.dylib", RTLD_NOW | RTLD_GLOBAL);
        if (!pam_lib) {
            fprintf(stderr, "dlopen failed for system pam: %s\n", dlerror());
            dlclose(handle);
            return 1;
        }
        
        int (*sys_pam_start)(const char *, const char *, const struct pam_conv *, pam_handle_t **) = dlsym(pam_lib, "pam_start");
        int (*sys_pam_end)(pam_handle_t *, int) = dlsym(pam_lib, "pam_end");
        const char *(*sys_pam_strerror)(pam_handle_t *, int) = dlsym(pam_lib, "pam_strerror");
        
        struct pam_conv conv = { dummy_conv, NULL };
        pam_handle_t *pamh = NULL;
        int status = sys_pam_start("sudo", user, &conv, &pamh);
        if (status != PAM_SUCCESS) {
            fprintf(stderr, "pam_start failed with code %d\n", status);
            dlclose(handle);
            return 1;
        }

        /* Forward any command-line arguments to pam_sm_authenticate (e.g. debug, timeout=10) */
        const char *module_argv[16];
        int module_argc = 0;
        module_argv[module_argc++] = "debug";
        for (int i = 1; i < argc && module_argc < 16; i++) {
            module_argv[module_argc++] = argv[i];
        }

        int pam_res = auth_fn(pamh, 0, module_argc, module_argv);
        printf("pam_sm_authenticate returned: %d (%s)\n", pam_res, sys_pam_strerror(pamh, pam_res));

        sys_pam_end(pamh, pam_res);
        dlclose(handle);

        return (pam_res == PAM_SUCCESS) ? 0 : 1;
    }
}
