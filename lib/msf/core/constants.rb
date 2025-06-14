# -*- coding: binary -*-
###
#
# This file contains constants that are referenced by the core
# framework and by framework modules.
#
###

module Msf

#
# Module types
#
MODULE_ANY     = '_any_'
MODULE_ENCODER = 'encoder'
MODULE_EXPLOIT = 'exploit'
MODULE_NOP     = 'nop'
MODULE_AUX     = 'auxiliary'
MODULE_PAYLOAD = 'payload'
MODULE_POST    = 'post'
MODULE_EVASION = 'evasion'
MODULE_TYPES   =
  [
    MODULE_ENCODER,
    MODULE_PAYLOAD,
    MODULE_EXPLOIT,
    MODULE_NOP,
    MODULE_POST,
    MODULE_AUX,
    MODULE_EVASION
  ]

#
# Module rankings
#
ManualRanking       = 0
LowRanking          = 100
AverageRanking      = 200
NormalRanking       = 300
GoodRanking         = 400
GreatRanking        = 500
ExcellentRanking    = 600
RankingName         =
  {
    ManualRanking    => "manual",
    LowRanking       => "low",
    AverageRanking   => "average",
    NormalRanking    => "normal",
    GoodRanking      => "good",
    GreatRanking     => "great",
    ExcellentRanking => "excellent"
  }

#
# Stability traits
#

# Module should not crash the service.
CRASH_SAFE             = 'crash-safe'
# Module may crash the service, but the service restarts.
CRASH_SERVICE_RESTARTS = 'crash-service-restarts'
# Module may crash the service, and the service remains down.
CRASH_SERVICE_DOWN     = 'crash-service-down'
# Module may crash the OS, but the OS restarts.
CRASH_OS_RESTARTS      = 'crash-os-restarts'
# Module may crash the OS, and the OS remains down.
CRASH_OS_DOWN          = 'crash-os-down'
# Module may cause a resource (such as a file or data in a database) to be unavailable for the service.
SERVICE_RESOURCE_LOSS  = 'service-resource-loss'
# Modules may cause a resource (such as a file) to be unavailable for the OS.
OS_RESOURCE_LOSS       = 'os-resource-loss'

#
# Side-effect traits
#

# Modules leaves a payload or a dropper on the target machine.
ARTIFACTS_ON_DISK = 'artifacts-on-disk'
# Module modifies some configuration setting on the target machine.
CONFIG_CHANGES    = 'config-changes'
# Module leaves signs of a compromise in a log file (Example: SQL injection data found in HTTP log).
IOC_IN_LOGS       = 'ioc-in-logs'
# Module may cause account lockouts (likely due to brute-forcing).
ACCOUNT_LOCKOUTS  = 'account-lockouts'
# Module may cause an existing valid session to be forced to log out (likely due to restrictions on concurrent sessions).
ACCOUNT_LOGOUT    = 'account-logout'
# Module may show something on the screen (Example: a window pops up).
SCREEN_EFFECTS    = 'screen-effects'
# Module may cause a noise (Examples: audio output from the speakers or hardware beeps).
AUDIO_EFFECTS     = 'audio-effects'
# Module may produce physical effects (Examples: the device makes movement or flashes LEDs).
PHYSICAL_EFFECTS  = 'physical-effects'

#
# Reliability
#

# The module tends to fail to get a session on the first attempt.
FIRST_ATTEMPT_FAIL = 'first-attempt-fail'
# The module is expected to get a shell every time it runs.
REPEATABLE_SESSION = 'repeatable-session'
# The module isn't expected to get a shell reliably (such as only once).
UNRELIABLE_SESSION = 'unreliable-session'
# The module may not execute the payload until an external event occurs. For instance, a cron job, machine restart, user interaction within a GUI element, etc.
EVENT_DEPENDENT = 'event-dependent'

module HttpClients
  IE = "MSIE"
  FF = "Firefox"
  SAFARI = "Safari"
  OPERA  = "Opera"
  CHROME = "Chrome"
  EDGE = "Edge"
  GIT = "Git"
  GIT_LFS = "Git LFS"

  UNKNOWN = "Unknown"
end

module OperatingSystems
  LINUX   = "Linux"
  MAC_OSX = "Mac OS X"
  WINDOWS = "Windows"
  FREEBSD = "FreeBSD"
  NETBSD  = "NetBSD"
  OPENBSD = "OpenBSD"
  VMWARE  = "VMware"
  ANDROID = "Android"
  APPLE_IOS = "iOS"

  module VmwareVersions
    ESX   = "ESX"
    ESXI  = "ESXi"
  end

  module WindowsVersions
    NINE5 = "95"
    NINE8 = "98"
    NT    = "NT"
    XP    = "XP"
    TWOK  = "2000"
    TWOK3 = "2003"
    VISTA = "Vista"
    TWOK8 = "2008"
    TWOK12 = "2012"
    SEVEN = "7"
    EIGHT = "8"
    EIGHTONE = "8.1"
    TEN = "10.0"
  end

  UNKNOWN = "Unknown"

  module Match
    WINDOWS         = /^(?:Microsoft )?Windows/
    WINDOWS_95      = /^(?:Microsoft )?Windows 95/
    WINDOWS_98      = /^(?:Microsoft )?Windows 98/
    WINDOWS_ME      = /^(?:Microsoft )?Windows ME/
    WINDOWS_NT3     = /^(?:Microsoft )?Windows NT 3/
    WINDOWS_NT4     = /^(?:Microsoft )?Windows NT 4/
    WINDOWS_2000    = /^(?:Microsoft )?Windows 2000/
    WINDOWS_XP      = /^(?:Microsoft )?Windows XP/
    WINDOWS_2003    = /^(?:Microsoft )?Windows 2003/
    WINDOWS_VISTA   = /^(?:Microsoft )?Windows Vista/
    WINDOWS_2008    = /^(?:Microsoft )?Windows 2008/
    WINDOWS_7       = /^(?:Microsoft )?Windows 7/
    WINDOWS_2012    = /^(?:Microsoft )?Windows 2012/
    WINDOWS_8       = /^(?:Microsoft )?Windows 8/
    WINDOWS_81      = /^(?:Microsoft )?Windows 8\.1/
    WINDOWS_10      = /^(?:Microsoft )?Windows 10/

    LINUX      = /^Linux/i
    MAC_OSX    = /^(?:Apple )?Mac OS X/
    FREEBSD    = /^FreeBSD/
    NETBSD     = /^NetBSD/
    OPENBSD    = /^OpenBSD/
    VMWARE     = /^VMware/
    ANDROID    = /^(?:Google )?Android/
    APPLE_IOS  = /^(?:Apple )?iOS/
  end
end
end

#
# Global constants
#

# Licenses
MSF_LICENSE      = "Metasploit Framework License (BSD)"
GPL_LICENSE      = "GNU Public License v2.0"
BSD_LICENSE      = "BSD License"
# Location: https://github.com/CoreSecurity/impacket/blob/1dba4c20e0d47ec614521e251d072116f75f3ef8/LICENSE
CORE_LICENSE     = "CORE Security License (Apache 1.1)"
ARTISTIC_LICENSE = "Perl Artistic License"
UNKNOWN_LICENSE  = "Unknown License"
LICENSES         =
  [
    MSF_LICENSE,
    GPL_LICENSE,
    BSD_LICENSE,
    CORE_LICENSE,
    ARTISTIC_LICENSE,
    UNKNOWN_LICENSE
  ]
