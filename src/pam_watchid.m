/*
 * pam_watchid — Pluggable Authentication Module (PAM) for Apple Watch double-click approval.
 *
 * Target: macOS 15+ (Sequoia / Tahoe), Apple Silicon, watchOS 10+.
 *
 * Architecture & Design:
 * =======================
 * This module enables macOS CLI tools (primarily `sudo`) to request user authorization
 * via a paired Apple Watch. It interfaces with Apple's LocalAuthentication framework
 * (`LAContext`) using the companion policy (`LAPolicyDeviceOwnerAuthenticationWithCompanion`).
 *
 * Key Security & Systems Features:
 * --------------------------------
 * 1. Security & Anti-Confused-Deputy:
 *    - Validates that the user attempting authentication or the target account matches
 *      the active GUI WindowServer console owner via SystemConfiguration
 *      (`SCDynamicStoreCopyConsoleUser`). This prevents non-console users, SSH actors,
 *      or background daemons from triggering prompts on the physical user's watch.
 *    - Rejects remote sessions (detecting `PAM_RHOST` and SSH environments).
 *
 * 2. Informative Multi-Line Structured Card:
 *    - Formats the localized reason into a structured, readable card for watchOS:
 *        "sudo is trying to run '<command>'
 *         • Target: <user> on <ComputerName>
 *         • Dir: <cwd>
 *         • Via: <parent_process> (<tty>)"
 *      This allows the wearer to immediately verify the command, target privileges,
 *      working directory, and originating process before approving.
 *
 * 3. Responsive Concurrency & Terminal Cancellation:
 *    - Asynchronously evaluates policy while synchronously awaiting response on the PAM thread.
 *    - Attaches a Grand Central Dispatch (GCD) signal source for `SIGINT` (Control-C).
 *      When interrupted in the terminal, it immediately invokes `[context invalidate]`,
 *      dismissing the prompt on both the Mac screen and Apple Watch without hanging.
 *    - Imposes a bounded timeout (default: 30 seconds) to ensure `sudo` never deadlocks
 *      if coreauthd stalls or Bluetooth communication fails.
 *
 * 4. OpenPAM & API Compliance:
 *    - Respects the `PAM_SILENT` flag.
 *    - Maps `LAError` domain codes cleanly to PAM standards (`PAM_SUCCESS`, `PAM_AUTH_ERR`,
 *      `PAM_AUTHINFO_UNAVAIL`).
 *    - Exports `pam_sm_authenticate`, `pam_sm_setcred`, and `pam_sm_acct_mgmt`, returning
 *      `PAM_SUCCESS` for credential/account stubs to align with Apple's native `pam_tid.so.2`.
 */

#import <Foundation/Foundation.h>
#import <LocalAuthentication/LocalAuthentication.h>
#import <SystemConfiguration/SystemConfiguration.h>
#import <libproc.h>
#import <os/log.h>

#include <dispatch/dispatch.h>
#include <pwd.h>
#include <signal.h>
#include <string.h>
#include <sys/sysctl.h>
#include <unistd.h>

#define PAM_SM_AUTH
#define PAM_SM_ACCOUNT
#include <security/pam_appl.h>
#include <security/pam_modules.h>

/* Default maximum duration (in seconds) to wait for an Apple Watch double-click. */
static const int64_t kDefaultTimeoutSec = 30;

/*
 * LAPolicyDeviceOwnerAuthenticationWithCompanion requires authentication via a paired
 * companion device (Apple Watch). On macOS 15+, this is the modern replacement for
 * the deprecated LAPolicyDeviceOwnerAuthenticationWithWatch.
 */
static const LAPolicy kPolicy = LAPolicyDeviceOwnerAuthenticationWithCompanion;

/*
 * Runtime configuration options parsed from the PAM configuration line in /etc/pam.d/
 * Example:
 *   auth sufficient pam_watchid.so debug timeout=15 reason="authorize root action"
 */
typedef struct {
    BOOL debug;              /* Whether to emit diagnostic logs to os_log. */
    int64_t timeoutSec;      /* Maximum duration to wait before timing out. */
    NSString *customReason;  /* User-override for the localized reason string. */
} pam_options_t;

/**
 * Parses command-line arguments passed to the PAM module in pam.d configuration.
 *
 * Supported arguments:
 *   - `debug`: Enables debug log messages to subsystem `org.pam.watchid`.
 *   - `timeout=<seconds>`: Overrides the default 30-second evaluation timeout.
 *   - `reason=<string>`: Overrides the dynamic prompt with custom reason text.
 *
 * @param argc Number of module arguments.
 * @param argv Array of argument strings.
 * @return Parsed options struct.
 */
static pam_options_t parse_options(int argc, const char **argv) {
    pam_options_t opts = {
        .debug = NO,
        .timeoutSec = kDefaultTimeoutSec,
        .customReason = nil,
    };

    for (int i = 0; i < argc; i++) {
        if (!argv[i]) continue;
        if (strcmp(argv[i], "debug") == 0) {
            opts.debug = YES;
        } else if (strncmp(argv[i], "timeout=", 8) == 0) {
            int val = atoi(argv[i] + 8);
            if (val > 0) opts.timeoutSec = val;
        } else if (strncmp(argv[i], "reason=", 7) == 0) {
            const char *val = argv[i] + 7;
            if (*val) opts.customReason = [NSString stringWithUTF8String:val];
        }
    }
    return opts;
}

/**
 * Validates that the authentication attempt corresponds to the active GUI console user.
 *
 * Security Context:
 * LocalAuthentication's Apple Watch companion policy triggers prompts on the watch paired
 * with the owner of the active WindowServer GUI console. If a different user (or an attacker
 * with background/remote shell access) invokes PAM, prompting the console owner's watch could
 * trick them into approving an unauthorized action (confused-deputy attack).
 *
 * Validation Logic:
 * 1. For root target authentications (typical `sudo`):
 *    Verifies that the calling user (from `getuid()`) matches the active console user UID.
 * 2. For non-root target authentications (e.g. `su <user>` or `sudo -u <user>`):
 *    Verifies that the target username matches the active console username.
 *
 * @param target_username The username PAM is authenticating for.
 * @param log os_log handle for diagnostic output.
 * @return YES if the caller is authorized to use the console user's Apple Watch; NO otherwise.
 */
static BOOL is_console_user(const char *target_username, os_log_t log) {
    if (target_username == NULL || *target_username == '\0') {
        return NO;
    }

    uid_t console_uid = 0;
    CFStringRef console_user_cf = SCDynamicStoreCopyConsoleUser(NULL, &console_uid, NULL);
    if (console_user_cf == NULL) {
        os_log_debug(log, "No active console user found in SystemConfiguration dynamic store.");
        return NO;
    }

    /* Transfer ownership of the CFStringRef to ARC as an NSString. */
    NSString *console_user = (__bridge_transfer NSString *)console_user_cf;
    uid_t caller_uid = getuid();

    /* Case 1: Standard sudo (target is root). Confirm the invoking user owns the console. */
    if (strcmp(target_username, "root") == 0) {
        if (caller_uid == console_uid || caller_uid == 0) {
            return YES;
        }
        os_log_debug(log, "Caller UID %u does not match active console user UID %u.", caller_uid, console_uid);
        return NO;
    }

    /* Case 2: Explicit target user. Confirm target matches the active console user. */
    if ([console_user isEqualToString:[NSString stringWithUTF8String:target_username]]) {
        return YES;
    }

    os_log_debug(log, "Target user '%s' does not match active console user '%{public}@'.",
                 target_username, console_user);
    return NO;
}

/**
 * Retrieves the human-readable computer name or host name for the prompt.
 *
 * Prioritizes the localized Computer Name (e.g., "Pierre's MacBook Pro" or "Caladan")
 * from SystemConfiguration, falling back to the POSIX hostname (stripping ".local").
 *
 * @return Friendly hostname string.
 */
static NSString *get_computer_name(void) {
    CFStringEncoding encoding = kCFStringEncodingUTF8;
    CFStringRef compName = SCDynamicStoreCopyComputerName(NULL, &encoding);
    if (compName != NULL) {
        return (__bridge_transfer NSString *)compName;
    }

    char host[256];
    if (gethostname(host, sizeof(host)) == 0 && host[0] != '\0') {
        char *dot = strstr(host, ".local");
        if (dot) *dot = '\0';
        return [NSString stringWithUTF8String:host];
    }
    return @"Mac";
}

/**
 * Retrieves a compact, human-readable representation of the current working directory.
 *
 * Replaces `$HOME` with `~` for brevity and truncates deeply nested directory trees
 * to the last two path components (e.g. `.../overlays/pam-watchid`).
 *
 * @return Compact directory path.
 */
static NSString *get_short_cwd(void) {
    char cwd[PATH_MAX];
    if (getcwd(cwd, sizeof(cwd)) == NULL) {
        return @".";
    }
    NSString *path = [NSString stringWithUTF8String:cwd];
    NSString *home = NSHomeDirectory();
    if ([path hasPrefix:home]) {
        path = [@"~" stringByAppendingString:[path substringFromIndex:home.length]];
    }
    if (path.length > 32) {
        NSArray<NSString *> *components = [path pathComponents];
        if (components.count > 3) {
            path = [NSString stringWithFormat:@".../%@/%@",
                    components[components.count - 2],
                    components[components.count - 1]];
        }
    }
    return path;
}

/**
 * Identifies the parent process and terminal TTY invoking sudo.
 *
 * Queries `libproc` (`proc_name`) for the parent process name (e.g., `zsh`, `make`, `npm`)
 * and retrieves the current TTY device (e.g., `ttys002`).
 *
 * @return Formatted string, e.g. "zsh (ttys002)".
 */
static NSString *get_parent_and_tty(void) {
    pid_t ppid = getppid();
    char pName[256] = {0};
    if (proc_name(ppid, pName, sizeof(pName)) <= 0 || pName[0] == '\0') {
        strncpy(pName, "unknown", sizeof(pName));
    }

    const char *tty = ttyname(STDIN_FILENO);
    if (tty != NULL) {
        if (strncmp(tty, "/dev/", 5) == 0) {
            tty += 5;
        }
    } else {
        tty = "no-tty";
    }

    return [NSString stringWithFormat:@"%s (%s)", pName, tty];
}

/**
 * Inspects the invoking process's command line arguments to identify the target command.
 *
 * Mechanism:
 * Uses macOS `sysctl(KERN_PROCARGS2)` on the current process ID (`getpid()`).
 * This yields the complete argument vector passed to the process (including `sudo`).
 *
 * Parsing Logic:
 * - If the calling binary is not `sudo` (e.g., `su`, `login`), returns `getprogname()`.
 * - For `sudo`:
 *   - Skips the `sudo` binary name and option flags (e.g., `-E`, `-u <user>`, `-g <group>`).
 *   - Detects special shell flags `-s` or `-i` and labels them as "shell".
 *   - Stops parsing options at the first non-option token or `--` delimiter.
 *   - Formats the resulting command and arguments, truncating excessively long strings
 *     (> 48 chars) with ellipsis ("...") to ensure clean rendering on watchOS.
 *
 * @return Formatted command string for the prompt.
 */
static NSString *get_target_command(void) {
    const char *prog = getprogname();
    if (prog == NULL || strcmp(prog, "sudo") != 0) {
        return prog ? [NSString stringWithUTF8String:prog] : @"command";
    }

    int mib[3] = { CTL_KERN, KERN_PROCARGS2, getpid() };
    size_t size = 0;
    if (sysctl(mib, 3, NULL, &size, NULL, 0) != 0 || size == 0) {
        return @"command";
    }

    char *buffer = malloc(size);
    if (!buffer) return @"command";

    if (sysctl(mib, 3, buffer, &size, NULL, 0) != 0) {
        free(buffer);
        return @"command";
    }

    /*
     * Memory Layout of KERN_PROCARGS2 buffer:
     *   [int argc]
     *   [null-terminated executable path]
     *   [zero or more null padding bytes]
     *   [null-terminated argv[0]]
     *   [null-terminated argv[1]] ...
     */
    int proc_argc = *(int *)buffer;
    char *p = buffer + sizeof(int);

    /* Skip executable path */
    while (*p != '\0') p++;
    /* Skip null padding */
    while (*p == '\0') p++;

    NSMutableArray<NSString *> *args = [NSMutableArray array];
    for (int i = 0; i < proc_argc && (p - buffer) < (ptrdiff_t)size; i++) {
        [args addObject:[NSString stringWithUTF8String:p]];
        p += strlen(p) + 1;
    }
    free(buffer);

    NSMutableArray<NSString *> *cmdParts = [NSMutableArray array];
    BOOL skipNext = NO;
    BOOL pastOptions = NO;

    for (NSUInteger i = 1; i < args.count; i++) {
        NSString *arg = args[i];
        if (skipNext) {
            skipNext = NO;
            continue;
        }

        if (!pastOptions) {
            if ([arg isEqualToString:@"--"]) {
                pastOptions = YES;
                continue;
            }
            if ([arg isEqualToString:@"-s"] || [arg isEqualToString:@"-i"]) {
                return @"shell";
            }
            /* Skip sudo option flags that consume a trailing value argument */
            if ([arg isEqualToString:@"-u"] || [arg isEqualToString:@"-g"] ||
                [arg isEqualToString:@"-p"] || [arg isEqualToString:@"-C"] ||
                [arg isEqualToString:@"-U"] || [arg isEqualToString:@"-D"] ||
                [arg isEqualToString:@"-R"]) {
                skipNext = YES;
                continue;
            }
            if ([arg hasPrefix:@"-"]) {
                continue;
            }
            /* First non-option argument encountered is the target command */
            pastOptions = YES;
        }

        [cmdParts addObject:arg];
    }

    if (cmdParts.count == 0) {
        return @"command";
    }

    NSString *cmdString = [cmdParts componentsJoinedByString:@" "];
    if (cmdString.length > 48) {
        cmdString = [NSString stringWithFormat:@"%@...", [cmdString substringToIndex:45]];
    }
    return cmdString;
}

/**
 * PAM Authentication Entry Point.
 *
 * Evaluates Apple Watch double-click confirmation for the calling session.
 *
 * Sequence of Execution:
 * ----------------------
 * 1. PAM_SILENT Check: Bail out immediately if the caller requested no interactive UI.
 * 2. Remote Session Detection: Reject incoming network connections (PAM_RHOST) to prevent
 *    remote command execution from vibrating the physical user's watch.
 * 3. Identity Verification: Query target username via pam_get_user.
 * 4. Console Ownership: Confirm that the user matches the active GUI session via is_console_user.
 * 5. TTY Verification: Ensure the session is interactive.
 * 6. LocalAuthentication Preflight: Synchronously evaluate whether Apple Watch companion
 *    unlock is enrolled and currently available (Bluetooth enabled, watch paired, etc.).
 * 7. Multi-Line Structured Card Generation:
 *      "sudo is trying to run '<command>'
 *       • Target: <user> on <host>
 *       • Dir: <cwd>
 *       • Via: <parent_process> (<tty>)"
 * 8. Signal Handler: Bind a GCD signal source to SIGINT (Control-C) so terminal interrupts
 *    immediately call [context invalidate] and close the watch/macOS UI prompt.
 * 9. Bounded Evaluation: Wait for asynchronous evaluation up to timeoutSec. If timed out,
 *    invalidate the context and cleanly report PAM_AUTHINFO_UNAVAIL.
 *
 * @param pamh PAM transaction handle.
 * @param flags PAM flags (e.g. PAM_SILENT).
 * @param argc Number of module configuration arguments.
 * @param argv Array of module configuration argument strings.
 * @return PAM status code (PAM_SUCCESS, PAM_AUTH_ERR, PAM_AUTHINFO_UNAVAIL, PAM_USER_UNKNOWN).
 */
PAM_EXTERN int
pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    os_log_t log = os_log_create("org.pam.watchid", "auth");
    pam_options_t opts = parse_options(argc, argv);

    /* 1. Respect PAM_SILENT: Do not present visual or haptic notifications if silence requested. */
    if (flags & PAM_SILENT) {
        if (opts.debug) os_log_debug(log, "PAM_SILENT requested; skipping prompt.");
        return PAM_AUTHINFO_UNAVAIL;
    }

    /* 2. Disallow remote connections (e.g. SSH): Protect against unauthorized remote triggers. */
    const void *rhost = NULL;
    if (pam_get_item(pamh, PAM_RHOST, &rhost) == PAM_SUCCESS && rhost != NULL) {
        if (strlen((const char *)rhost) > 0) {
            if (opts.debug) os_log_debug(log, "Remote session detected (%{public}s); skipping.", (const char *)rhost);
            return PAM_AUTHINFO_UNAVAIL;
        }
    }

    /* 3. Validate PAM target user. */
    const char *username = NULL;
    if (pam_get_user(pamh, &username, NULL) != PAM_SUCCESS || username == NULL) {
        os_log_error(log, "Unable to obtain PAM username.");
        return PAM_USER_UNKNOWN;
    }

    /* 4. Enforce console user matching (Anti-Confused-Deputy). */
    if (!is_console_user(username, log)) {
        if (opts.debug) os_log_debug(log, "Console user mismatch; skipping watch prompt.");
        return PAM_AUTHINFO_UNAVAIL;
    }

    /* 5. Check interactive terminal: Fall back if stdin is not a TTY and SSH is detected. */
    if (!isatty(STDIN_FILENO) && getenv("SSH_CONNECTION") != NULL) {
        return PAM_AUTHINFO_UNAVAIL;
    }

    __block int result = PAM_AUTH_ERR;

    @autoreleasepool {
        /*
         * NS_VALID_UNTIL_END_OF_SCOPE:
         * ARC's optimizer under -O2 may insert an early release for `context` immediately
         * after `evaluatePolicy:` if no lexical references follow. Because LAContext dealloc
         * treats active evaluations as cancellation, premature deallocation would orphan
         * the reply block and cause the wait to block forever.
         */
        NS_VALID_UNTIL_END_OF_SCOPE LAContext *context = [[LAContext alloc] init];
        if (context == nil) {
            os_log_error(log, "Failed to instantiate LAContext.");
            return PAM_AUTHINFO_UNAVAIL;
        }

        /* 6. Synchronous preflight check: Bails immediately if watch is locked, absent, or disabled. */
        NSError *preflightError = nil;
        if (![context canEvaluatePolicy:kPolicy error:&preflightError]) {
            if (opts.debug) {
                os_log_debug(log, "canEvaluatePolicy preflight failed: %{public}@", preflightError.localizedDescription);
            }
            return PAM_AUTHINFO_UNAVAIL;
        }

        /* 7. Build localized reason text: Multi-Line Structured Card for Mac dialog. */
        NSString *reason = opts.customReason;
        if (!reason) {
            NSString *command = get_target_command();
            NSString *host = get_computer_name();
            NSString *dir = get_short_cwd();
            NSString *via = get_parent_and_tty();

            reason = [NSString stringWithFormat:
                @"run '%@'\n"
                @"• Target: %s on %@\n"
                @"• Dir: %@\n"
                @"• Via: %@",
                command, username, host, dir, via];
        }

        /* Suppress the default "Enter Password" button in the LA prompt so PAM controls password fallback. */
        context.localizedFallbackTitle = @"";

        dispatch_semaphore_t done = dispatch_semaphore_create(0);

        /*
         * 8. Terminal Cancellation (Control-C / SIGINT):
         * Libdispatch semaphores do not return EINTR when a POSIX signal arrives.
         * We attach a dedicated GCD signal event handler for SIGINT. When the user hits
         * Control-C in the terminal, the handler triggers `[context invalidate]`.
         * Invalidation immediately dismisses the prompt on macOS and watchOS and calls
         * the reply block with LAErrorAppCancel, unblocking the PAM thread cleanly.
         */
        dispatch_source_t sigSource = dispatch_source_create(
            DISPATCH_SOURCE_TYPE_SIGNAL,
            SIGINT,
            0,
            dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_HIGH, 0)
        );

        if (sigSource) {
            dispatch_source_set_event_handler(sigSource, ^{
                os_log_debug(log, "SIGINT caught; cancelling watch prompt.");
                [context invalidate];
            });
            dispatch_resume(sigSource);
        }

        [context evaluatePolicy:kPolicy
                localizedReason:reason
                          reply:^(BOOL success, NSError *error) {
            if (success) {
                result = PAM_SUCCESS;
            } else if (error != nil && [error.domain isEqualToString:LAErrorDomain]) {
                if (opts.debug) fprintf(stderr, "LAError code: %ld\n", (long)error.code);
                switch (error.code) {
                    case LAErrorUserCancel:
                        /* Explicit user cancellation: fail auth to stop the chain. */
                        result = PAM_AUTH_ERR;
                        break;
                    case LAErrorUserFallback:
                    case LAErrorCompanionNotAvailable:
                    case LAErrorBiometryNotAvailable:
                    case LAErrorBiometryNotEnrolled:
                    case LAErrorNotInteractive:
                    case LAErrorPasscodeNotSet:
                    case LAErrorSystemCancel:
                    case LAErrorAppCancel:
                        /* Factor unavailable or cancelled by app/system: fall through to password module. */
                        result = PAM_AUTHINFO_UNAVAIL;
                        break;
                    default:
                        result = PAM_AUTH_ERR;
                        break;
                }
            } else {
                if (opts.debug && error) fprintf(stderr, "Unknown error: %s\n", error.description.UTF8String);
                result = PAM_AUTH_ERR;
            }
            dispatch_semaphore_signal(done);
        }];

        /*
         * 9. Bounded Wait with Timeout:
         * Prevents sudo from freezing indefinitely if coreauthd stalls or Bluetooth drops.
         * If the timeout expires, invalidate the context to dismiss the alert dialog and
         * allow up to 1 second for the reply block to complete cleanly before returning.
         */
        dispatch_time_t timeout = dispatch_time(DISPATCH_TIME_NOW, opts.timeoutSec * NSEC_PER_SEC);
        if (dispatch_semaphore_wait(done, timeout) != 0) {
            os_log_error(log, "Authentication timed out after %lld seconds.", opts.timeoutSec);
            [context invalidate];
            dispatch_semaphore_wait(done, dispatch_time(DISPATCH_TIME_NOW, 1 * NSEC_PER_SEC));
            result = PAM_AUTHINFO_UNAVAIL;
        }

        /* Teardown the signal handler to restore standard terminal behavior */
        if (sigSource) {
            dispatch_source_cancel(sigSource);
        }
    }

    if (opts.debug) os_log_debug(log, "pam_sm_authenticate finished with code %d", result);
    return result;
}

/**
 * PAM Credential Management Entry Point.
 *
 * This module does not manage ticket caches, Kerberos tokens, or session keys.
 * Returning PAM_SUCCESS mirrors Apple's native `pam_tid.so.2` implementation, ensuring
 * that `pam_setcred` succeeds during sudo session initialization.
 */
PAM_EXTERN int
pam_sm_setcred(pam_handle_t *pamh __unused, int flags __unused,
               int argc __unused, const char **argv __unused) {
    return PAM_SUCCESS;
}

/**
 * PAM Account Management Entry Point.
 *
 * Exported to ensure that if pam_watchid is referenced across generic or account
 * management chains, OpenPAM does not encounter missing symbol errors.
 */
PAM_EXTERN int
pam_sm_acct_mgmt(pam_handle_t *pamh __unused, int flags __unused,
                 int argc __unused, const char **argv __unused) {
    return PAM_SUCCESS;
}
