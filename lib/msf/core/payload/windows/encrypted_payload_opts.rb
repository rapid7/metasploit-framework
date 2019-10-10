require 'msf/core'

module Msf
  module Payload::Windows::EncryptedPayloadOpts
    include Msf::Payload::UUID::Options

    LINK_SCRIPT_PATH = File.join(Msf::Config.install_root, 'data', 'utilities', 'encrypted_payload')

    def initialize(info={})
      super

      register_options(
      [
        OptBool.new('CallWSAStartup', [ false, 'Adds the function that initializes the Winsock library', true ]),
        OptString.new('ChachaKey', [ false, 'The initial key to encrypt payload traffic with', Rex::Text.rand_text_alphanumeric(32) ]),
        OptString.new('ChachaNonce', [ false, 'The initial nonce to use to encrypt payload traffic with', Rex::Text.rand_text_alphanumeric(12) ])
      ], self.class)

      register_advanced_options(
      [
        OptBool.new('StripSymbols', [ false, 'Payload will be compiled without symbols', true ]),
        OptString.new('OptLevel', [ false, 'The optimization level to compile with, e.g. O1, O2, O3, Os', 'O2' ]),
        OptPath.new('LinkerScript', [ false, 'Linker script that orders payload functions', "#{LINK_SCRIPT_PATH}/func_order.ld" ]),
        OptBool.new('PayloadUUIDTracking', [ true, 'Whether or not to automatically register generated UUIDs', true ])
      ], self.class)
    end
  end
end
