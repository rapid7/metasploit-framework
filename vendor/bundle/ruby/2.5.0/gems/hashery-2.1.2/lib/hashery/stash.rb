require 'hashery/key_hash'

module Hashery
  # Stash is the original name for the KeyHash.
  Stash = KeyHash
end

class Hash
  # Convert Hash to Stash.
  def to_stash
    Hashery::Stash[self]
  end
end

