require 'hashery/crud_hash'

module Hashery

  # The KeyHash class is a Hash class which accepts a block for
  # normalizing keys.
  #
  # The KeyHash class is essentially the same as a normal Hash.
  # But notice the significant distinction of indifferent key
  # access.
  # 
  #   s = KeyHash.new
  #   s[:x] = 1
  #   s[:x]       #=> 1
  #   s['x']      #=> 1
  # 
  # We can see that internally the key has indeed been converted
  # to a String.
  # 
  #   s.to_h      #=> {'x'=>1 }
  # 
  # By default all keys are converted to strings. This has two advantages
  # over a regular Hash is many usecases. First it means hash entries have
  # indifferent access. <tt>1</tt>, <tt>"1"</tt> and <tt>:1</tt> are all
  # equivalent --any object that defines <tt>#to_s</tt> can be used as a key.
  # Secondly, since strings are garbage collected so will default KeyHash
  # objects. 
  # 
  # But keys can be normalized by any function. Theses functions can be quite
  # unique.
  #
  #   h = KeyHash.new(0){ |k| k.to_i }
  #   h[1.34] += 1
  #   h[1.20] += 1
  #   h[1.00] += 1
  #   h  #=> { 1 => 3 }
  #
  class KeyHash < CRUDHash

    #
    # Unlike a regular Hash, a KeyHash's block sets the `key_proc` rather
    # than the `default_proc`.
    #
    def initialize(*default, &block)
      super(*default)
      @key_proc = block || Proc.new{ |k| k.to_s }
    end

  end

end

#class Hash
#  #
#  # Convert a Hash to a KeyHash object.
#  #
#  def to_keyhash
#    Hashery::KeyHash[self]
#  end
#end

