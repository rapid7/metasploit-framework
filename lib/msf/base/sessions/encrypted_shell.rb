# -*- coding: binary -*-
require 'msf/base'
require 'securerandom'
require 'msf/core/payload/windows/payload_db_conf'

module Msf
module Sessions

class EncryptedShell < Msf::Sessions::CommandShell

  include Msf::Session::Basic
  include Msf::Session::Provider::SingleCommandShell
  include Msf::Payload::Windows::PayloadDBConf

  attr_accessor :arch
  attr_accessor :platform

  attr_accessor :iv
  attr_accessor :key
  attr_accessor :staged

  # define some sort of method that checks for
  # the existence of payload in the db before
  # using datastore
  def initialize(rstream, opts={})
    self.arch ||= ""
    self.platform = "windows"
    @staged = opts[:datastore][:staged]
    super
  end

  def type
    "Encrypted"
  end

  def desc
    "Encrypted reverse shell"
  end

  def self.type
    self.class.type = "Encrypted"
  end

  def process_autoruns(datastore)
    @key = datastore[:key] || datastore['ChachaKey']
    nonce = datastore[:nonce] || datastore['ChachaNonce']
    @iv = nonce

    # staged payloads retrieve UUID via
    # handle_connection() in stager.rb
    unless @staged
      curr_uuid = rstream.get_once(16, 1)
      @key, @nonce = retrieve_chacha_creds(curr_uuid)
      @iv = @nonce ? @nonce : "\0" * 12

      unless @key && @nonce
        print_status('Failed to retrieve key/nonce for uuid. Resorting to datastore')
        @key = datastore['ChachaKey']
        @iv = datastore['ChachaNonce']
      end
    end

    new_nonce = SecureRandom.hex(6)
    new_key = SecureRandom.hex(16)
    new_cipher = Rex::Crypto.chacha_encrypt(@key, @iv, new_nonce + new_key)
    rstream.write(new_cipher)

    @key = new_key
    @iv = new_nonce
  end

  ##
  # Overridden from Msf::Sessions::CommandShell#shell_read
  #
  # Read encrypted data from console and decrypt it
  #
  def shell_read(length=-1, timeout=1)
    rv = rstream.get_once(length, timeout)
    decrypted = Rex::Crypto.chacha_decrypt(@key, @iv, rv)
    framework.events.on_session_output(self, decrypted) if decrypted
    return decrypted
  rescue ::Rex::SocketError, ::EOFError, ::IOError, ::Errno::EPIPE => e
    shell_close
    raise e
  end

  ##
  # Overridden from Msf::Sessions::CommandShell#shell_write
  #
  # Encrypt data then write it to the console
  #
  def shell_write(buf)
    return unless buf

    framework.events.on_session_command(self, buf.strip)
    encrypted = Rex::Crypto.chacha_encrypt(@key, @iv, buf)
    rstream.write(encrypted)
  rescue ::Rex::SocketError, ::EOFError, ::IOError, ::Errno::EPIPE => e
    shell_close
    raise e
  end

end
end
end
