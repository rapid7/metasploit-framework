# -*- coding: binary -*-
require 'rex/post/meterpreter/extensions/stdapi/railgun/const_manager'

module Rex
module Post
module Meterpreter
module Extensions
module Stdapi
module Railgun
module Def

#
# A container holding useful OSX API Constants.
#
class DefApiConstants_osx < ApiConstants

  #
  # Slurp in a giant list of known constants.
  #
  def self.add_constants(const_mgr)
    # https://opensource.apple.com/source/xnu/xnu-2050.18.24/bsd/sys/socket.h
    const_mgr.add_const('AF_UNSPEC',         0x00000000)
    const_mgr.add_const('AF_LOCAL',          0x00000001)
    const_mgr.add_const('AF_UNIX',           0x00000001)
    const_mgr.add_const('AF_INET',           0x00000002)
    const_mgr.add_const('AF_INET6',          0x0000001e)

    # https://opensource.apple.com/source/xnu/xnu-2050.18.24/bsd/sys/mman.h
    const_mgr.add_const('MAP_FILE',       0x0000)
    const_mgr.add_const('MAP_SHARED',     0x0001)
    const_mgr.add_const('MAP_PRIVATE',    0x0002)
    const_mgr.add_const('MAP_FIXED',      0x0010)
    const_mgr.add_const('MAP_ANON',       0x1000)
    const_mgr.add_const('MAP_ANONYMOUS',  0x1000)
    const_mgr.add_const('PROT_NONE',      0x0000)
    const_mgr.add_const('PROT_READ',      0x0001)
    const_mgr.add_const('PROT_WRITE',     0x0002)
    const_mgr.add_const('PROT_EXEC',      0x0004)

    # https://opensource.apple.com/source/dyld/dyld-95.3/include/dlfcn.h
    const_mgr.add_const('RTLD_LAZY',      0x0001)
    const_mgr.add_const('RTLD_NOW',       0x0002)
    const_mgr.add_const('RTLD_LOCAL',     0x0004)
    const_mgr.add_const('RTLD_GLOBAL',    0x0008)
    const_mgr.add_const('RTLD_NOLOAD',    0x0010)
    const_mgr.add_const('RTLD_NODELETE',  0x0080)
    const_mgr.add_const('RTLD_FIRST',     0x0100)  # Mac OS X 10.5 and later

  end
end

end; end; end; end; end; end; end
