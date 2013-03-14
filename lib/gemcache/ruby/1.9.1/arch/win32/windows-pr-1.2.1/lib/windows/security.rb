require 'windows/api'

# The auto_unicode option has been set to false because the majority of
# the methods defined here do not have explicit ANSI or Wide character
# versions.

module Windows
  module Security
    API.auto_namespace = 'Windows::Security'
    API.auto_constant  = true
    API.auto_method    = true
    API.auto_unicode   = false

    private

    ACL_REVISION                   = 2
    ACL_REVISION1                  = 1
    ACL_REVISION2                  = 2
    ACL_REVISION3                  = 3
    ACL_REVISION4                  = 4
    ALLOW_ACE_LENGTH               = 62
    DACL_SECURITY_INFORMATION      = 4
    SE_DACL_PRESENT                = 4
    SECURITY_DESCRIPTOR_MIN_LENGTH = 20
    SECURITY_DESCRIPTOR_REVISION   = 1
    SECURITY_DESCRIPTOR_REVISION1  = 1
    
    SECURITY_NULL_SID_AUTHORITY         = 0
    SECURITY_WORLD_SID_AUTHORITY        = 1
    SECURITY_LOCAL_SID_AUTHORITY        = 2
    SECURITY_CREATOR_SID_AUTHORITY      = 3
    SECURITY_NON_UNIQUE_AUTHORITY       = 4
    SECURITY_NT_AUTHORITY               = 5
    SECURITY_RESOURCE_MANAGER_AUTHORITY = 9      

    SECURITY_NULL_RID                 = 0x00000000
    SECURITY_WORLD_RID                = 0x00000000
    SECURITY_LOCAL_RID                = 0x00000000
    SECURITY_CREATOR_OWNER_RID        = 0x00000000
    SECURITY_CREATOR_GROUP_RID        = 0x00000001
    SECURITY_CREATOR_OWNER_SERVER_RID = 0x00000002
    SECURITY_CREATOR_GROUP_SERVER_RID = 0x00000003
    SECURITY_DIALUP_RID               = 0x00000001
    SECURITY_NETWORK_RID              = 0x00000002
    SECURITY_BATCH_RID                = 0x00000003
    SECURITY_INTERACTIVE_RID          = 0x00000004
    SECURITY_LOGON_IDS_RID            = 0x00000005
    SECURITY_LOGON_IDS_RID_COUNT      = 3
    SECURITY_SERVICE_RID              = 0x00000006
    SECURITY_ANONYMOUS_LOGON_RID      = 0x00000007
    SECURITY_PROXY_RID                = 0x00000008

    SECURITY_ENTERPRISE_CONTROLLERS_RID   = 0x00000009
    SECURITY_SERVER_LOGON_RID             = SECURITY_ENTERPRISE_CONTROLLERS_RID
    SECURITY_PRINCIPAL_SELF_RID           = 0x0000000A
    SECURITY_AUTHENTICATED_USER_RID       = 0x0000000B
    SECURITY_RESTRICTED_CODE_RID          = 0x0000000C
    SECURITY_TERMINAL_SERVER_RID          = 0x0000000D
    SECURITY_REMOTE_LOGON_RID             = 0x0000000E
    SECURITY_THIS_ORGANIZATION_RID        = 0x0000000F
    SECURITY_LOCAL_SYSTEM_RID             = 0x00000012
    SECURITY_LOCAL_SERVICE_RID            = 0x00000013
    SECURITY_NETWORK_SERVICE_RID          = 0x00000014
    SECURITY_NT_NON_UNIQUE                = 0x00000015
    SECURITY_NT_NON_UNIQUE_SUB_AUTH_COUNT = 3

    SECURITY_BUILTIN_DOMAIN_RID     = 0x00000020
    SECURITY_PACKAGE_BASE_RID       = 0x00000040
    SECURITY_PACKAGE_RID_COUNT      = 2
    SECURITY_PACKAGE_NTLM_RID       = 0x0000000A
    SECURITY_PACKAGE_SCHANNEL_RID   = 0x0000000E
    SECURITY_PACKAGE_DIGEST_RID     = 0x00000015
    SECURITY_MAX_ALWAYS_FILTERED    = 0x000003E7
    SECURITY_MIN_NEVER_FILTERED     = 0x000003E8

    SECURITY_OTHER_ORGANIZATION_RID     = 0x000003E8
    FOREST_USER_RID_MAX                 = 0x000001F3
    DOMAIN_USER_RID_ADMIN               = 0x000001F4
    DOMAIN_USER_RID_GUEST               = 0x000001F5
    DOMAIN_USER_RID_KRBTGT              = 0x000001F6
    DOMAIN_USER_RID_MAX                 = 0x000003E7
    DOMAIN_GROUP_RID_ADMINS             = 0x00000200
    DOMAIN_GROUP_RID_USERS              = 0x00000201
    DOMAIN_GROUP_RID_GUESTS             = 0x00000202
    DOMAIN_GROUP_RID_COMPUTERS          = 0x00000203
    DOMAIN_GROUP_RID_CONTROLLERS        = 0x00000204
    DOMAIN_GROUP_RID_CERT_ADMINS        = 0x00000205
    DOMAIN_GROUP_RID_SCHEMA_ADMINS      = 0x00000206
    DOMAIN_GROUP_RID_ENTERPRISE_ADMINS  = 0x00000207
    DOMAIN_GROUP_RID_POLICY_ADMINS      = 0x00000208
    DOMAIN_ALIAS_RID_ADMINS             = 0x00000220
    DOMAIN_ALIAS_RID_USERS              = 0x00000221
    DOMAIN_ALIAS_RID_GUESTS             = 0x00000222
    DOMAIN_ALIAS_RID_POWER_USERS        = 0x00000223
    DOMAIN_ALIAS_RID_ACCOUNT_OPS        = 0x00000224
    DOMAIN_ALIAS_RID_SYSTEM_OPS         = 0x00000225
    DOMAIN_ALIAS_RID_PRINT_OPS          = 0x00000226
    DOMAIN_ALIAS_RID_BACKUP_OPS         = 0x00000227
    DOMAIN_ALIAS_RID_REPLICATOR         = 0x00000228
    DOMAIN_ALIAS_RID_RAS_SERVERS        = 0x00000229

    DOMAIN_ALIAS_RID_PREW2KCOMPACCESS               = 0x0000022A
    DOMAIN_ALIAS_RID_REMOTE_DESKTOP_USERS           = 0x0000022B
    DOMAIN_ALIAS_RID_NETWORK_CONFIGURATION_OPS      = 0x0000022C
    DOMAIN_ALIAS_RID_INCOMING_FOREST_TRUST_BUILDERS = 0x0000022D
    DOMAIN_ALIAS_RID_MONITORING_USERS               = 0x0000022E
    DOMAIN_ALIAS_RID_LOGGING_USERS                  = 0x0000022F
    DOMAIN_ALIAS_RID_AUTHORIZATIONACCESS            = 0x00000230
    DOMAIN_ALIAS_RID_TS_LICENSE_SERVERS             = 0x00000231
    DOMAIN_ALIAS_RID_DCOM_USERS                     = 0x00000232
    
    GENERIC_RIGHTS_MASK = 0xF0010000
    GENERIC_RIGHTS_CHK  = 0xF0000000
    REST_RIGHTS_MASK    = 0x001FFFFF

    TOKEN_READ              = 131080
    TOKEN_WRITE             = 131296
    TOKEN_EXECUTE           = 131072
    TOKEN_ASSIGN_PRIMARY    = 0x0001
    TOKEN_DUPLICATE         = 0x0002
    TOKEN_IMPERSONATE       = 0x0004
    TOKEN_QUERY             = 0x0008
    TOKEN_QUERY_SOURCE      = 0x0010
    TOKEN_ADJUST_PRIVILEGES = 0x0020
    TOKEN_ADJUST_GROUPS     = 0x0040
    TOKEN_ADJUST_DEFAULT    = 0x0080
    TOKEN_ADJUST_SESSIONID  = 0x0100
    TOKEN_ALL_ACCESS_P      = 983295 # Calculated from WinNt.h
    TOKEN_ALL_ACCESS        = TOKEN_ALL_ACCESS_P | TOKEN_ADJUST_SESSIONID
    
    SE_PRIVILEGE_ENABLED_BY_DEFAULT = 0x00000001
    SE_PRIVILEGE_ENABLED            = 0x00000002
    SE_PRIVILEGE_REMOVED            = 0X00000004
    SE_PRIVILEGE_USED_FOR_ACCESS    = 0x80000000      

    OWNER_SECURITY_INFORMATION = 1
    GROUP_SECURITY_INFORMATION = 2

    # SE_OBJECT_TYPE Enumeration

    SE_UNKNOWN_OBJECT_TYPE     = 0
    SE_FILE_OBJECT             = 1
    SE_SERVICE                 = 2
    SE_PRINTER                 = 3
    SE_REGISTRY_KEY            = 4
    SE_LMSHARE                 = 5
    SE_KERNEL_OBJECT           = 6
    SE_WINDOW_OBJECT           = 7
    SE_DS_OBJECT               = 8
    SE_DS_OBJECT_ALL           = 9
    SE_PROVIDER_DEFINED_OBJECT = 10
    SE_WMIGUID_OBJECT          = 11
    SE_REGISTRY_WOW64_32KEY    = 12

    # Defined Privileges

    SE_CREATE_TOKEN_NAME        = "SeCreateTokenPrivilege"
    SE_ASSIGNPRIMARYTOKEN_NAME  = "SeAssignPrimaryTokenPrivilege"
    SE_LOCK_MEMORY_NAME         = "SeLockMemoryPrivilege"
    SE_INCREASE_QUOTA_NAME      = "SeIncreaseQuotaPrivilege"
    SE_UNSOLICITED_INPUT_NAME   = "SeUnsolicitedInputPrivilege"
    SE_MACHINE_ACCOUNT_NAME     = "SeMachineAccountPrivilege"
    SE_TCB_NAME                 = "SeTcbPrivilege"
    SE_SECURITY_NAME            = "SeSecurityPrivilege"
    SE_TAKE_OWNERSHIP_NAME      = "SeTakeOwnershipPrivilege"
    SE_LOAD_DRIVER_NAME         = "SeLoadDriverPrivilege"
    SE_SYSTEM_PROFILE_NAME      = "SeSystemProfilePrivilege"
    SE_SYSTEMTIME_NAME          = "SeSystemtimePrivilege"
    SE_PROF_SINGLE_PROCESS_NAME = "SeProfileSingleProcessPrivilege"
    SE_INC_BASE_PRIORITY_NAME   = "SeIncreaseBasePriorityPrivilege"
    SE_CREATE_PAGEFILE_NAME     = "SeCreatePagefilePrivilege"
    SE_CREATE_PERMANENT_NAME    = "SeCreatePermanentPrivilege"
    SE_BACKUP_NAME              = "SeBackupPrivilege"
    SE_RESTORE_NAME             = "SeRestorePrivilege"
    SE_SHUTDOWN_NAME            = "SeShutdownPrivilege"
    SE_DEBUG_NAME               = "SeDebugPrivilege"
    SE_AUDIT_NAME               = "SeAuditPrivilege"
    SE_SYSTEM_ENVIRONMENT_NAME  = "SeSystemEnvironmentPrivilege"
    SE_CHANGE_NOTIFY_NAME       = "SeChangeNotifyPrivilege"
    SE_REMOTE_SHUTDOWN_NAME     = "SeRemoteShutdownPrivilege"
    SE_UNDOCK_NAME              = "SeUndockPrivilege"
    SE_SYNC_AGENT_NAME          = "SeSyncAgentPrivilege"
    SE_ENABLE_DELEGATION_NAME   = "SeEnableDelegationPrivilege"
    SE_MANAGE_VOLUME_NAME       = "SeManageVolumePrivilege"
    SE_IMPERSONATE_NAME         = "SeImpersonatePrivilege"
    SE_CREATE_GLOBAL_NAME       = "SeCreateGlobalPrivilege"

    ACCESS_MIN_MS_ACE_TYPE                  = 0x0
    ACCESS_ALLOWED_ACE_TYPE                 = 0x0
    ACCESS_DENIED_ACE_TYPE                  = 0x1
    SYSTEM_AUDIT_ACE_TYPE                   = 0x2
    SYSTEM_ALARM_ACE_TYPE                   = 0x3
    ACCESS_MAX_MS_V2_ACE_TYPE               = 0x3
    ACCESS_ALLOWED_COMPOUND_ACE_TYPE        = 0x4
    ACCESS_MAX_MS_V3_ACE_TYPE               = 0x4
    ACCESS_MIN_MS_OBJECT_ACE_TYPE           = 0x5
    ACCESS_ALLOWED_OBJECT_ACE_TYPE          = 0x5
    ACCESS_DENIED_OBJECT_ACE_TYPE           = 0x6
    SYSTEM_AUDIT_OBJECT_ACE_TYPE            = 0x7
    SYSTEM_ALARM_OBJECT_ACE_TYPE            = 0x8
    ACCESS_MAX_MS_OBJECT_ACE_TYPE           = 0x8
    ACCESS_MAX_MS_V4_ACE_TYPE               = 0x8
    ACCESS_MAX_MS_ACE_TYPE                  = 0x8
    ACCESS_ALLOWED_CALLBACK_ACE_TYPE        = 0x9
    ACCESS_DENIED_CALLBACK_ACE_TYPE         = 0xA
    ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE = 0xB
    ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE  = 0xC
    SYSTEM_AUDIT_CALLBACK_ACE_TYPE          = 0xD
    SYSTEM_ALARM_CALLBACK_ACE_TYPE          = 0xE
    SYSTEM_AUDIT_CALLBACK_OBJECT_ACE_TYPE   = 0xF
    SYSTEM_ALARM_CALLBACK_OBJECT_ACE_TYPE   = 0x10
    ACCESS_MAX_MS_V5_ACE_TYPE               = 0x10
    OBJECT_INHERIT_ACE                      = 0x1
    CONTAINER_INHERIT_ACE                   = 0x2
    NO_PROPAGATE_INHERIT_ACE                = 0x4
    INHERIT_ONLY_ACE                        = 0x8
    INHERITED_ACE                           = 0x10
    VALID_INHERIT_FLAGS                     = 0x1F
    SUCCESSFUL_ACCESS_ACE_FLAG              = 0x40
    FAILED_ACCESS_ACE_FLAG                  = 0x80

    # Standard Access Rights

    DELETE                       = 0x00010000
    READ_CONTROL                 = 0x20000
    WRITE_DAC                    = 0x40000
    WRITE_OWNER                  = 0x80000
    SYNCHRONIZE                  = 0x100000
    STANDARD_RIGHTS_REQUIRED     = 0xf0000
    STANDARD_RIGHTS_READ         = 0x20000
    STANDARD_RIGHTS_WRITE        = 0x20000
    STANDARD_RIGHTS_EXECUTE      = 0x20000
    STANDARD_RIGHTS_ALL          = 0x1F0000
    SPECIFIC_RIGHTS_ALL          = 0xFFFF
    ACCESS_SYSTEM_SECURITY       = 0x1000000
    MAXIMUM_ALLOWED              = 0x2000000
    GENERIC_READ                 = 0x80000000
    GENERIC_WRITE                = 0x40000000
    GENERIC_EXECUTE              = 0x20000000
    GENERIC_ALL                  = 0x10000000

    # Enum SidNameUse

    SidTypeUser           = 1
    SidTypeGroup          = 2
    SidTypeDomain         = 3
    SidTypeAlias          = 4
    SidTypeWellKnownGroup = 5
    SidTypeDeletedAccount = 6
    SidTypeInvalid        = 7
    SidTypeUnknown        = 8
    SidTypeComputer       = 9

    # Enum TokenInformationClass

    TokenUser                  = 1
    TokenGroups                = 2
    TokenPrivileges            = 3               
    TokenOwner                 = 4
    TokenPrimaryGroup          = 5
    TokenDefaultDacl           = 6
    TokenSource                = 7
    TokenType                  = 8
    TokenImpersonationLevel    = 9
    TokenStatistics            = 10
    TokenRestrictedSids        = 11
    TokenSessionId             = 12
    TokenGroupsAndPrivileges   = 13
    TokenSessionReference      = 14
    TokenSandBoxInert          = 15
    TokenAuditPolicy           = 16
    TokenOrigin                = 17
    TokenElevationType         = 18
    TokenLinkedToken           = 19
    TokenElevation             = 20
    TokenHasRestrictions       = 21
    TokenAccessInformation     = 22
    TokenVirtualizationAllowed = 23
    TokenVirtualizationEnabled = 24
    TokenIntegrityLevel        = 25
    TokenUIAccess              = 26
    TokenMandatoryPolicy       = 27
    TokenLogonSid              = 28
    MaxTokenInfoClass          = 29

    # Enum WellKnownSidType

    WinNullSid                                    = 0
    WinWorldSid                                   = 1
    WinLocalSid                                   = 2
    WinCreatorOwnerSid                            = 3
    WinCreatorGroupSid                            = 4
    WinCreatorOwnerServerSid                      = 5
    WinCreatorGroupServerSid                      = 6
    WinNtAuthoritySid                             = 7
    WinDialupSid                                  = 8
    WinNetworkSid                                 = 9
    WinBatchSid                                   = 10
    WinInteractiveSid                             = 11
    WinServiceSid                                 = 12
    WinAnonymousSid                               = 13
    WinProxySid                                   = 14
    WinEnterpriseControllersSid                   = 15
    WinSelfSid                                    = 16
    WinAuthenticatedUserSid                       = 17
    WinRestrictedCodeSid                          = 18
    WinTerminalServerSid                          = 19
    WinRemoteLogonIdSid                           = 20
    WinLogonIdsSid                                = 21
    WinLocalSystemSid                             = 22
    WinLocalServiceSid                            = 23
    WinNetworkServiceSid                          = 24
    WinBuiltinDomainSid                           = 25
    WinBuiltinAdministratorsSid                   = 26
    WinBuiltinUsersSid                            = 27
    WinBuiltinGuestsSid                           = 28
    WinBuiltinPowerUsersSid                       = 29
    WinBuiltinAccountOperatorsSid                 = 30
    WinBuiltinSystemOperatorsSid                  = 31
    WinBuiltinPrintOperatorsSid                   = 32
    WinBuiltinBackupOperatorsSid                  = 33
    WinBuiltinReplicatorSid                       = 34
    WinBuiltinPreWindows2000CompatibleAccessSid   = 35
    WinBuiltinRemoteDesktopUsersSid               = 36
    WinBuiltinNetworkConfigurationOperatorsSid    = 37
    WinAccountAdministratorSid                    = 38
    WinAccountGuestSid                            = 39
    WinAccountKrbtgtSid                           = 40
    WinAccountDomainAdminsSid                     = 41
    WinAccountDomainUsersSid                      = 42
    WinAccountDomainGuestsSid                     = 43
    WinAccountComputersSid                        = 44
    WinAccountControllersSid                      = 45
    WinAccountCertAdminsSid                       = 46
    WinAccountSchemaAdminsSid                     = 47
    WinAccountEnterpriseAdminsSid                 = 48
    WinAccountPolicyAdminsSid                     = 49
    WinAccountRasAndIasServersSid                 = 50
    WinNTLMAuthenticationSid                      = 51
    WinDigestAuthenticationSid                    = 52
    WinSChannelAuthenticationSid                  = 53
    WinThisOrganizationSid                        = 54
    WinOtherOrganizationSid                       = 55
    WinBuiltinIncomingForestTrustBuildersSid      = 56
    WinBuiltinPerfMonitoringUsersSid              = 57
    WinBuiltinPerfLoggingUsersSid                 = 58
    WinBuiltinAuthorizationAccessSid              = 59
    WinBuiltinTerminalServerLicenseServersSid     = 60
    WinBuiltinDCOMUsersSid                        = 61
    WinBuiltinIUsersSid                           = 62
    WinIUserSid                                   = 63
    WinBuiltinCryptoOperatorsSid                  = 64
    WinUntrustedLabelSid                          = 65
    WinLowLabelSid                                = 66
    WinMediumLabelSid                             = 67
    WinHighLabelSid                               = 68
    WinSystemLabelSid                             = 69
    WinWriteRestrictedCodeSid                     = 70
    WinCreatorOwnerRightsSid                      = 71
    WinCacheablePrincipalsGroupSid                = 72
    WinNonCacheablePrincipalsGroupSid             = 73
    WinEnterpriseReadonlyControllersSid           = 74
    WinAccountReadonlyControllersSid              = 75
    WinBuiltinEventLogReadersGroup                = 76
    WinNewEnterpriseReadonlyControllersSid        = 77
    WinBuiltinCertSvcDComAccessGroup              = 78
    
    # Enum AclInformationClass

    AclRevisionInformation = 1
    AclSizeInformation     = 2

    API.new('AccessCheck', 'PLLPPLPP', 'B', 'advapi32')
    API.new('AccessCheckAndAuditAlarm', 'SLPPPLPIPPP', 'B', 'advapi32')
    API.new('AccessCheckByType', 'PPLLPLPPPPP', 'B', 'advapi32')
    API.new('AccessCheckByTypeAndAuditAlarm', 'SLSSPPLLLPLLIPPP', 'B', 'advapi32')
    API.new('AccessCheckByTypeResultList', 'PPLLPLPPPPP', 'B', 'advapi32')
    API.new('AccessCheckByTypeResultListAndAuditAlarm', 'SLSSLPLLLPLLIPPP', 'B', 'advapi32')
    API.new('AddAccessAllowedAce', 'PLLP', 'B', 'advapi32')
    API.new('AddAccessAllowedAceEx', 'PLLLP', 'B', 'advapi32')
    API.new('AddAccessAllowedObjectAce', 'PLLLPPP', 'B', 'advapi32')
    API.new('AddAccessDeniedAce', 'PLLP', 'B', 'advapi32')
    API.new('AddAccessDeniedAceEx', 'PLLLP', 'B', 'advapi32')
    API.new('AddAccessDeniedObjectAce', 'PLLLPPP', 'B', 'advapi32')
    API.new('AddAce', 'PLLLL', 'B', 'advapi32')
    API.new('AddAuditAccessAce', 'PLLPII', 'B', 'advapi32')
    API.new('AddAuditAccessAceEx', 'PLLLPII', 'B', 'advapi32')
    API.new('AddAuditAccessObjectAce', 'PLLLPPPII', 'B', 'advapi32')
    API.new('AdjustTokenGroups', 'LLPLPP', 'B', 'advapi32')
    API.new('AdjustTokenPrivileges', 'LLPLPP', 'B', 'advapi32')
    API.new('AllocateAndInitializeSid', 'PLLLLLLLLLP', 'B', 'advapi32')
    API.new('AllocateLocallyUniqueId', 'P', 'B', 'advapi32')
    API.new('AreAllAccessesGranted', 'LL', 'B', 'advapi32')
    API.new('AreAnyAccessesGranted', 'LL', 'B', 'advapi32')
    API.new('CheckTokenMembership', 'LPP', 'B', 'advapi32')
    API.new('CopySid', 'LLP', 'B', 'advapi32')
    API.new('ConvertSidToStringSid', 'LP', 'B', 'advapi32')
    API.new('ConvertSecurityDescriptorToStringSecurityDescriptor', 'PLLPP', 'B', 'advapi32')
    API.new('ConvertStringSecurityDescriptorToSecurityDescriptor', 'PLPP', 'B', 'advapi32')
    API.new('ConvertStringSidToSid', 'LP', 'B', 'advapi32')
    API.new('CreateRestrictedToken', 'LLLPLPLPP', 'B', 'advapi32')
    API.new('DeleteAce', 'PL', 'B', 'advapi32')
    API.new('DuplicateToken', 'LPP', 'B', 'advapi32')
    API.new('DuplicateTokenEx', 'LLPLLP', 'B', 'advapi32')
    API.new('EqualPrefixSid', 'PP', 'B', 'advapi32')
    API.new('EqualSid', 'PP', 'B', 'advapi32')
    API.new('FindFirstFreeAce', 'PP', 'B', 'advapi32')
    API.new('FreeSid', 'P', 'L', 'advapi32')
    API.new('GetAce', 'LLP', 'B', 'advapi32')
    API.new('GetAclInformation', 'PPLI', 'B', 'advapi32')
    API.new('GetFileSecurity', 'PLPLP', 'B', 'advapi32')
    API.new('GetFileSecurityA', 'PLPLP', 'B', 'advapi32')
    API.new('GetFileSecurityW', 'PLPLP', 'B', 'advapi32')
    API.new('GetLengthSid', 'P', 'L', 'advapi32')
    API.new('GetSecurityDescriptorControl', 'PPP', 'B', 'advapi32')
    API.new('GetSecurityDescriptorDacl', 'PPPP', 'B', 'advapi32')
    API.new('GetSecurityDescriptorGroup', 'PPI', 'B', 'advapi32')
    API.new('GetSecurityDescriptorLength', 'P', 'L', 'advapi32')
    API.new('GetSecurityDescriptorOwner', 'PPI', 'B', 'advapi32')
    API.new('GetSecurityDescriptorRMControl', 'PP', 'L', 'advapi32')
    API.new('GetSecurityDescriptorSacl', 'PIPI', 'B', 'advapi32')
    API.new('GetSecurityInfo', 'LLLPPPPP', 'L', 'advapi32')
    API.new('GetTokenInformation', 'LLPLP', 'B', 'advapi32')
    API.new('GetSidIdentifierAuthority', 'P', 'L', 'advapi32')
    API.new('GetSidLengthRequired', 'I', 'L', 'advapi32')
    API.new('GetSidSubAuthority', 'PL', 'L', 'advapi32')
    API.new('GetSidSubAuthorityCount', 'P', 'L', 'advapi32')
    API.new('GetUserObjectSecurity', 'LPPLP', 'B', 'user32')
    API.new('GetWindowsAccountDomainSid', 'PPP', 'B', 'advapi32')
    API.new('InitializeAcl', 'PLL', 'B', 'advapi32')
    API.new('InitializeSecurityDescriptor', 'PL', 'B', 'advapi32')
    API.new('InitializeSid', 'PPI', 'B', 'advapi32')
    API.new('IsTokenRestricted', 'L', 'B', 'advapi32')
    API.new('IsValidAcl', 'P', 'B', 'advapi32')
    API.new('IsValidSecurityDescriptor', 'P', 'B', 'advapi32')
    API.new('IsValidSid', 'P', 'B', 'advapi32')
    API.new('LookupAccountName', 'PPPPPPP', 'B', 'advapi32')
    API.new('LookupAccountSid', 'PLPPPPP', 'B', 'advapi32')
    API.new('LookupPrivilegeDisplayName', 'PPPPP', 'B', 'advapi32')
    API.new('LookupPrivilegeName', 'PPPP', 'B', 'advapi32')
    API.new('LookupPrivilegeValue', 'PPP', 'B', 'advapi32')
    API.new('OpenProcessToken', 'LLP', 'B', 'advapi32')
    API.new('OpenThreadToken', 'LLLP', 'B', 'advapi32')
    API.new('SetAclInformation', 'PPLL', 'B', 'advapi32')
    API.new('SetEntriesInAcl', 'LPPP', 'L', 'advapi32')
    API.new('SetFileSecurity', 'PPP', 'B', 'advapi32')
    API.new('SetFileSecurityA', 'PPP', 'B', 'advapi32')
    API.new('SetFileSecurityW', 'PPP', 'B', 'advapi32') 
    API.new('SetSecurityDescriptorDacl', 'PIPI', 'B', 'advapi32')
    API.new('SetSecurityDescriptorGroup', 'PPI', 'B', 'advapi32')
    API.new('SetSecurityDescriptorOwner', 'PPI', 'B', 'advapi32')
    API.new('SetSecurityDescriptorRMControl', 'PP', 'L', 'advapi32')
    API.new('SetSecurityDescriptorSacl', 'PIPI', 'B', 'advapi32')
    API.new('SetSecurityInfo', 'LLLPPPP', 'L', 'advapi32')
    API.new('SetThreadToken', 'PL', 'B', 'advapi32')
    API.new('SetTokenInformation', 'LLPL', 'B', 'advapi32')
    API.new('SetUserObjectSecurity', 'LPP', 'B', 'user32')

    begin
      API.new('CreateWellKnownSid', 'IPPP', 'B', 'advapi32')
      API.new('AddMandatoryAce', 'PLLLP', 'B', 'advapi32')
      API.new('EqualDomainSid', 'PPP', 'B', 'advapi32')
      API.new('FreeInheritedFromArray', 'PIP', 'B', 'advapi32')
      API.new('GetInheritanceSource', 'PLLIPLPPLP', 'L', 'advapi32')
      API.new('IsWellKnownSid', 'PI', 'B', 'advapi32')
    rescue Win32::API::LoadLibraryError
      # Windows XP or later
    end

    begin
      API.new('AuditComputeEffectivePolicyBySid', 'PPLP', 'B', 'advapi32')
      API.new('AuditComputeEffectivePolicyByToken', 'LPLP', 'B', 'advapi32')
      API.new('AuditEnumerateCategories', 'PP', 'B', 'advapi32')
      API.new('AuditEnumeratePerUserPolicy', 'P', 'B', 'advapi32')
    rescue Win32::API::LoadLibraryError
      # Windows Vista or later
    end
  end
end
