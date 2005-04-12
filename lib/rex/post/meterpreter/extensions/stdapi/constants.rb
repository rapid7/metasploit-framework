#!/usr/bin/ruby

###
#
# These are put into the global namespace for now
# so that they can be referenced globally
#
###

##
#
# Permissions
#
##
DELETE                   = 0x00010000
READ_CONTROL             = 0x00020000
WRITE_DAC                = 0x00040000
WRITE_OWNER              = 0x00080000
SYNCHRONIZE              = 0x00100000
STANDARD_RIGHTS_REQUIRED = 0x000f0000
STANDARD_RIGHTS_READ     = READ_CONTROL
STANDARD_RIGHTS_WRITE    = READ_CONTROL
STANDARD_RIGHTS_EXECUTE  = READ_CONTROL
STANDARD_RIGHTS_ALL      = 0x001f0000
SPECIFIC_RIGHTS_ALL      = 0x0000ffff
MAXIMUM_ALLOWED          = 0x02000000
GENERIC_READ             = 0x80000000
GENERIC_WRITE            = 0x40000000
GENERIC_EXECUTE          = 0x20000000
GENERIC_ALL              = 0x10000000

##
#
# Registry Permissions
#
##
KEY_QUERY_VALUE          = 0x00000001
KEY_SET_VALUE            = 0x00000002
KEY_CREATE_SUB_KEY       = 0x00000004
KEY_ENUMERATE_SUB_KEYS   = 0x00000008
KEY_NOTIFY               = 0x00000010
KEY_CREATE_LINK          = 0x00000020
KEY_READ                 = (STANDARD_RIGHTS_READ | KEY_QUERY_VALUE | 
                            KEY_ENUMERATE_SUB_KEYS | KEY_NOTIFY) & ~SYNCHRONIZE
KEY_WRITE                = (STANDARD_RIGHTS_WRITE | KEY_SET_VALUE | 
                            KEY_CREATE_SUB_KEY) & ~SYNCHRONIZE
KEY_EXECUTE              = KEY_READ
KEY_ALL_ACCESS           = (STANDARD_RIGHTS_ALL | KEY_QUERY_VALUE |
                            KEY_SET_VALUE | KEY_CREATE_SUB_KEY | 
                            KEY_ENUMERATE_SUB_KEYS | KEY_NOTIFY |
                            KEY_CREATE_LINK) & ~SYNCHRONIZE

##
#
# Registry
#
##
HKEY_CLASSES_ROOT        = 0x80000000
HKEY_CURRENT_USER        = 0x80000001
HKEY_LOCAL_MACHINE       = 0x80000002
HKEY_USERS               = 0x80000003
HKEY_PERFORMANCE_DATA    = 0x80000004
HKEY_CURRENT_CONFIG      = 0x80000005
HKEY_DYN_DATA            = 0x80000006

REG_NONE                 = 0
REG_SZ                   = 1
REG_EXPAND_SZ            = 2
REG_BINARY               = 3
REG_DWORD                = 4
REG_DWORD_LITTLE_ENDIAN  = 4
REG_DWORD_BIG_ENDIAN     = 5
REG_LINK                 = 6
REG_MULTI_SZ             = 7
