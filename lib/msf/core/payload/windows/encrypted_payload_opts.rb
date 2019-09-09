require 'msf/core'

module Msf
  module Payload::Windows::EncryptedReverseTcpOpts
    def initialize(*args)
      super

      register_options(
      [
        OptBool.new('CallWSAStartup', [ false, 'Adds the function that initializes the Winsock library', true ])
      ], self.class)

      register_advanced_options(
      [
        OptBool.new('StripSymbols', [ false, 'Payload will be compiled without symbols', true ])
      ], self.class)
    end
  end
end
