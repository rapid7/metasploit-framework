module RubySMB
  module Dcerpc
    module Srvsvc

      UUID = '4b324fc8-1670-01d3-1278-5a47bf6ee188'
      VER_MAJOR = 3
      VER_MINOR = 0

      # Operation numbers
      NET_SHARE_ENUM_ALL = 0xF

      require 'ruby_smb/dcerpc/srvsvc/net_share_enum_all'
    end
  end
end
