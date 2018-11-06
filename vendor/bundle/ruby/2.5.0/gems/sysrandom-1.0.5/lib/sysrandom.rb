require "sysrandom/version"

require "base64"

# Secure random number generation using system RNG facilities
module Sysrandom
  module_function

  # For some reason SecureRandom defaults to 16 bytes
  DEFAULT_LENGTH = 16

  if defined?(JRUBY_VERSION)
    require "java"

    begin
      # Try to use the new NativePRNGNonBlocking algorithm introduced in Java 8.
      @_java_secure_random = java.security.SecureRandom.getInstance("NativePRNGNonBlocking")
    rescue
      # If unavailable, fall back to the default configuration. This will
      # probably be SHA1PRNG, but it depends on the JRE's configuration.
      @_java_secure_random = java.security.SecureRandom.new
    end

    # Random uint32, used by random_number. The C extension provides an equivalent method
    def __random_uint32
      @_java_secure_random.nextLong & 0xFFFFFFFF
    end

    def random_bytes(n = nil)
      n ||= DEFAULT_LENGTH
      raise ArgumentError, "negative string size" if n < 0
      return "" if n == 0

      bytes = Java::byte[n].new
      @_java_secure_random.nextBytes(bytes)
      String.from_java_bytes(bytes)
    end
  else
    require "sysrandom_ext"
  end

  def random_number(n = 0)
    result = __random_uint32 / (2**32).to_f

    if n <= 0
      result
    else
      result *= n
      n.is_a?(Integer) ? result.floor : result
    end
  end

  def base64(n = nil)
    Base64.encode64(random_bytes(n)).chomp
  end

  def urlsafe_base64(n = nil, padding = false)
    result = Base64.urlsafe_encode64(random_bytes(n)).chomp
    padding ? result : result.tr("=", "")
  end

  def hex(n = nil)
    random_bytes(n).unpack("h*").first
  end

  def uuid
    values = hex(16).match(/\A(.{8})(.{4})(.)(.{3})(.)(.{3})(.{12})\z/)
    "#{values[1]}-#{values[2]}-4#{values[4]}-#{'89ab'[values[5].ord % 4]}#{values[6]}-#{values[7]}"
  end
end
