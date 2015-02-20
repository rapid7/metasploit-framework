# -*- coding: binary -*-
module Rex
module Platforms
module Windows



#
# Windows Registry Constants
#
  REG_NONE = 1
  REG_SZ = 1
  REG_EXPAND_SZ = 2
  REG_BINARY = 3
  REG_DWORD = 4
  REG_LITTLE_ENDIAN = 4
  REG_BIG_ENDIAN = 5
  REG_LINK = 6
  REG_MULTI_SZ = 7

  HKEY_CLASSES_ROOT = 0x80000000
  HKEY_CURRENT_USER = 0x80000001
  HKEY_LOCAL_MACHINE = 0x80000002
  HKEY_USERS = 0x80000003
  HKEY_PERFORMANCE_DATA = 0x80000004
  HKEY_CURRENT_CONFIG = 0x80000005
  HKEY_DYN_DATA = 0x80000006

  def registry_hive_lookup(hive)
    case hive
    when 'HKCR'
      HKEY_LOCAL_MACHINE
    when 'HKCU'
      HKEY_CURRENT_USER
    when 'HKLM'
      HKEY_LOCAL_MACHINE
    when 'HKU'
      HKEY_USERS
    when 'HKPD'
      HKEY_PERFORMANCE_DATA
    when 'HKCC'
      HKEY_CURRENT_CONFIG
    when 'HKDD'
      HKEY_DYN_DATA
    else
      HKEY_LOCAL_MACHINE
    end
  end

end
end
end
