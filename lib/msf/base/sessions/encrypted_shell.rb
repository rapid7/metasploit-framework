require 'msf/base'
require 'lib/rex/crypto/chacha20'

module Msf
module Sessions

class EncryptedCommandShell < CommandShell

  attr_accessor :arch
  attr_accessor :platform

  attr_reader :iv
  attr_reader :key
  attr_reader :cipher
  
  @key = "HKa1Rt3KdxCf35I3kS1RUGh6MXSfqEC4"
  @iv = "bCsEzT3QbCsE"

  def initialize(rstream, opts = {})
    self.arch ||= ""
    self.platform ||= ""
    @cipher = OpenSSL::Cipher.new('chacha20')
    @cipher.random_iv
    @cipher.random_key
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
