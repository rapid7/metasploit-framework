require 'msf/core'

module Msf
  module Payload::Windows::EncryptedPayloadOpts
    LINK_SCRIPT_PATH = File.join(Msf::Config.install_root, 'data', 'utilities', 'encrypted_payload', 'func_order.ld')

    def initialize(*args)
      super

      register_options(
      [
        OptBool.new('CallWSAStartup', [ false, 'Adds the function that initializes the Winsock library', true ])
      ], self.class)

      register_advanced_options(
      [
        OptBool.new('StripSymbols', [ false, 'Payload will be compiled without symbols', true ]),
        OptPath.new('LinkerScript', [ false, 'Linker script that orders payload functions', LINK_SCRIPT_PATH ])
      ], self.class)
    end
  end
end
