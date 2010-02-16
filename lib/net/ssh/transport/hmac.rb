require 'net/ssh/transport/hmac/md5'
require 'net/ssh/transport/hmac/md5_96'
require 'net/ssh/transport/hmac/sha1'
require 'net/ssh/transport/hmac/sha1_96'
require 'net/ssh/transport/hmac/none'

# Implements a simple factory interface for fetching hmac implementations, or
# for finding the key lengths for hmac implementations.s
module Net::SSH::Transport::HMAC
  # The mapping of SSH hmac algorithms to their implementations
  MAP = {
    'hmac-md5'     => MD5,
    'hmac-md5-96'  => MD5_96,
    'hmac-sha1'    => SHA1,
    'hmac-sha1-96' => SHA1_96,
    'none'         => None
  }

  # Retrieves a new hmac instance of the given SSH type (+name+). If +key+ is
  # given, the new instance will be initialized with that key.
  def self.get(name, key="")
    impl = MAP[name] or raise ArgumentError, "hmac not found: #{name.inspect}"
    impl.new(key)
  end

  # Retrieves the key length for the hmac of the given SSH type (+name+).
  def self.key_length(name)
    impl = MAP[name] or raise ArgumentError, "hmac not found: #{name.inspect}"
    impl.key_length
  end
end