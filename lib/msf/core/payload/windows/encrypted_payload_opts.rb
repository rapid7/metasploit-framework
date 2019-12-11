require 'msf/core'
require 'securerandom'

module Msf
  module Payload::Windows::EncryptedPayloadOpts
    include Msf::Payload::UUID::Options

    LINK_SCRIPT_PATH = File.join(Msf::Config.data_directory, 'utilities', 'encrypted_payload')

    def initialize(info={})
      super

      register_options(
      [
        OptBool.new('CallWSAStartup', [ false, 'Adds the function that initializes the Winsock library', true ]),
        OptString.new('ChachaKey', [ false, 'The initial key to encrypt payload traffic with', SecureRandom.hex(16) ]),
        OptString.new('ChachaNonce', [ false, 'The initial nonce to use to encrypt payload traffic with', SecureRandom.hex(6) ])
      ], self.class)

      register_advanced_options(
      [
        OptBool.new('StripSymbols', [ false, 'Payload will be compiled without symbols', true ]),
        OptEnum.new('OptLevel', [ false, 'The optimization level to compile with', 'O2', [ 'Og', 'Os', 'O0', 'O1', 'O2', 'O3' ] ]),
        OptBool.new('KeepSrc', [ false, 'Keep source code after compiling it', true ]),
        OptBool.new('KeepExe', [ false, 'Keep executable after compiling the payload', true ]),
        OptBool.new('PayloadUUIDTracking', [ true, 'Whether or not to automatically register generated UUIDs', true ])
      ], self.class)
    end
  end
end
