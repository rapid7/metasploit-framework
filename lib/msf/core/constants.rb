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

CRASH_SAFE             = 'Module should not crash the service'
CRASH_SERVICE_RESTARTS = 'Module may crash the service, but the service restarts'
CRASH_SERVICE_DOWN     = 'Module may crash the service, and the service remains down'
CRASH_OS_RESTARTS      = 'Module may crash the OS, but the OS restarts'
CRASH_OS_DOWN          = 'Module may crash the OS, and the OS remains down'
SERVICE_RESOURCE_LOSS  = 'Module may cause a resource (such as a file or data in database) to be unavailable for the service'
OS_RESOURCE_LOSS       = 'Module may cause a resource (such as a file) to be unavailable for the OS'

#
# Side-effect traits
#

ARTIFACTS_ON_DISK = 'Module leaves payload or a dropper on the target machine'
CONFIG_CHANGES    = 'Module modifies some config file on the target machine'
IOC_IN_LOGS       = 'Module leaves signs of a compromise in a log file (Example: SQL injection data found in HTTP log)'
ACCOUNT_LOCKOUTS  = 'Module may cause account lockouts (likely due to brute-forcing)'
SCREEN_EFFECTS    = 'Module may show something on the screen (Example: a window pops up)'
AUDIO_EFFECTS     = 'Module may cause a noise (Examples: audio output from the speakers or hardware beeps)'
PHYSICAL_EFFECTS  = 'Module may produce physical effects (Examples: the device makes movement or flashes LEDs)'

#
# Reliability
#

FIRST_ATTEMPT_FAIL = 'Module tends to fail to get a session at first attempt'
REPEATABLE_SESSION = 'Module is expected to get a shell every time it fires'
UNRELIABLE_SESSION = 'Module is not expected to get a shell reliably (such as only once)'

module HttpClients
  IE = "MSIE"
  FF = "Firefox"
  SAFARI = "Safari"
  OPERA  = "Opera"
  CHROME = "Chrome"
  EDGE = "Edge"

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
