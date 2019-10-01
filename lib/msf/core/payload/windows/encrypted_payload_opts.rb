require 'msf/core'

module Msf
  module Payload::Windows::EncryptedPayloadOpts
    LINK_SCRIPT_PATH = File.join(Msf::Config.install_root, 'data', 'utilities', 'encrypted_payload')

    def initialize(*args)
      super

      register_options(
      [
        OptBool.new('CallWSAStartup', [ false, 'Adds the function that initializes the Winsock library', true ]),
        OptString.new('ChachaKey', [ false, 'The initial key to encrypt payload traffic with', Rex::Text.rand_text_alphanumeric(32, (0x00..0x1f).to_a) ]),
        OptString.new('ChachaNonce', [ false, 'The initial nonce to use to encrypt payload traffic with', Rex::Text.rand_text_alphanumeric(12, (0x00..0x1f).to_a) ])
      ], self.class)

      register_advanced_options(
      [
        OptBool.new('StripSymbols', [ false, 'Payload will be compiled without symbols', true ]),
        OptPath.new('LinkerScript', [ false, 'Linker script that orders payload functions', "#{LINK_SCRIPT_PATH}/func_order.ld" ])
      ], self.class)
    end
  end
end
