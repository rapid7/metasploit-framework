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
MODULE_TYPES   =
  [
    MODULE_ENCODER,
    MODULE_PAYLOAD,
    MODULE_EXPLOIT,
    MODULE_NOP,
    MODULE_POST,
    MODULE_AUX
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

module HttpClients
  IE = "MSIE"
  FF = "Firefox"
  SAFARI = "Safari"
  OPERA  = "Opera"
  CHROME = "Chrome"

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
ARTISTIC_LICENSE = "Perl Artistic License"
UNKNOWN_LICENSE  = "Unknown License"
LICENSES         =
  [
    MSF_LICENSE,
    GPL_LICENSE,
    BSD_LICENSE,
    ARTISTIC_LICENSE,
    UNKNOWN_LICENSE
  ]
