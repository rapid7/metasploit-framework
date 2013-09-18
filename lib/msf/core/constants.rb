# -*- coding: binary -*-
###
#
# This file contains constants that are referenced by the core
# framework and by framework modules.
#
###

module Msf

  #
  # Module rankings
  #
  Metasploit::Model::Module::Rank::NUMBER_BY_NAME.each do |name, number|
    constant = "#{name}Ranking"
    const_set(constant, number)
  end


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
  WINDOWS = "Microsoft Windows"
  FREEBSD = "FreeBSD"
  NETBSD  = "NetBSD"
  OPENBSD = "OpenBSD"
  VMWARE  = "VMware"

  module VmwareVersions
    ESX   = "ESX"
    ESXI  = "ESXi"
  end

  module WindowsVersions
    NT    = "NT"
    XP    = "XP"
    TWOK  = "2000"
    TWOK3 = "2003"
    VISTA = "Vista"
    TWOK8 = "2008"
    SEVEN = "7"
  end

  UNKNOWN = "Unknown"
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

