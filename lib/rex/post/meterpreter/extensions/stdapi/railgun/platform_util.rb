# -*- coding: binary -*-
module Rex
module Post
module meeterpeter
module Extensions
module Stdapi
module Railgun
module PlatformUtil

  X86_64 = :x86_64
  X86_32 = :x86_32

  def self.parse_client_platform(meterp_client_platform)
    meterp_client_platform =~ /win64/ ? X86_64 : X86_32
  end

end # PlatformUtil
end # Railgun
end # Stdapi
end # Extensions
end # meeterpeter
end # Post
end # Rex
