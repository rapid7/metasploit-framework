#include "utils.h"

const char* spc_errors[] = {
    "",
    "Malformed bundle",
    "Invalid path",
    "Invalid property list",
    "Invalid or missing service identifier",
    "Invalid or missing Program/ProgramArguments",
    "Could not find specified domain",
    "Could not find specified service",
    "The specified username does not exist",
    "The specified group does not exist",
    "Routine not yet implemented",
    "(n/a)",
    "Bad response from server",
    "Service is disabled",
    "Bad subsystem destination for request",
    "Path not searched for services",
    "Path had bad ownership/permissions",
    "Path is whitelisted for domain",
    "Domain is tearing down",
    "omain does not support specified action",
    "Request type is no longer supported",
    "The specified service did not ship with the operating system",
    "The specified path is not a bundle",
    "The service was superseded by a later version",
    "The system encountered a condition where behavior was undefined",
    "Out of order requests",
    "Request for stale data",
    "Multiple errors were returned; see stderr",
    "Service cannot load in requested session",
    "Process is not managed",
    "Action not allowed on singleton service",
    "Service does not support the specified action",
    "Service cannot be loaded on this hardware",
    "Service cannot presently execute",
    "Service name is reserved or invalid",
    "Reentrancy avoided",
    "Operation only supported on development builds",
    "Requested entry was cached",
    "Requestor lacks required entitlement",
    "Endpoint is hidden",
    "Domain is in on-demand-only mode",
    "The specified service did not ship in the requestor",
    "The specified service path was not in the service cache",
    "Could not find a bundle of the given identifier through LaunchServices",
    "Operation not permitted while System Integrity Protection is engaged",
    "A complete hack",
    "Service cannot load in current boot environment",
    "Completely unexpected error",
    "Requestor is not a platform binary",
    "Refusing to execute/trust quarantined program/file",
    "Domain creation with that UID is not allowed anymore",
    "System service is not in system service whitelist",
    "Unknown error",
};

const char* spc_strerror(int errno)
{
    const char* result;
    if (errno - 107 >= 52)
        result = strerror(errno);
    else
        result = spc_errors[errno - 106];
    return result;
}

int mach_port_addref(mach_port_t port, mach_port_right_t right) {
    mach_port_urefs_t refs;
    kern_return_t kr = mach_port_get_refs(mach_task_self(), port, right, &refs);
    ASSERT_MACH_SUCCESS(kr, "mach_port_get_refs");
    ASSERT_MSG(refs != 0, "invalid mach port given to mach_port_addref");

    kr = mach_port_mod_refs(mach_task_self(), port, right, 1);
    ASSERT_MACH_SUCCESS(kr, "mach_port_mod_refs");

    return refs + 1;
}
