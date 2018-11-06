module RubySMB
  # Namespace for all of the packet Dispatcher code. This is what
  # handles network level transport.
  module Dispatcher
    require 'ruby_smb/dispatcher/base'
    require 'ruby_smb/dispatcher/socket'
  end
end
