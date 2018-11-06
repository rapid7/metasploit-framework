# frozen_string_literal: true
# A subclass of Hash where all keys are converted into Symbols, and
# optionally, all String values are converted into Symbols.
class SymbolHash < Hash
  # Creates a new SymbolHash object
  #
  # @param [Boolean] symbolize_value converts any String values into Symbols
  #   if this is set to +true+.
  def initialize(symbolize_value = true)
    @symbolize_value = symbolize_value
  end

  # @overload [](hash)
  #   Creates a SymbolHash object from an existing Hash
  #
  #   @example
  #     SymbolHash['x' => 1, :y => 2] # => #<SymbolHash:0x...>
  #   @param [Hash] hash the hash object
  #   @return [SymbolHash] a new SymbolHash from a hash object
  #
  # @overload [](*list)
  #   Creates a SymbolHash from an even list of keys and values
  #
  #   @example
  #     SymbolHash[key1, value1, key2, value2, ...]
  #   @param [Array] list an even list of key followed by value
  #   @return [SymbolHash] a new SymbolHash object
  def self.[](*hsh)
    obj = new
    if hsh.size == 1 && hsh.first.is_a?(Hash)
      hsh.first.each {|k, v| obj[k] = v }
    else
      0.step(hsh.size, 2) {|n| obj[hsh[n]] = hsh[n + 1] }
    end
    obj
  end

  # Assigns a value to a symbolized key
  # @param [#to_sym] key the key
  # @param [Object] value the value to be assigned. If this is a String and
  #   values are set to be symbolized, it will be converted into a Symbol.
  def []=(key, value)
    super(key.to_sym, value.instance_of?(String) && @symbolize_value ? value.to_sym : value)
  end

  # Accessed a symbolized key
  # @param [#to_sym] key the key to access
  # @return [Object] the value associated with the key
  def [](key) super(key.to_sym) end

  # Deleted a key and value associated with it
  # @param [#to_sym] key the key to delete
  # @return [void]
  def delete(key) super(key.to_sym) end

  # Tests if a symbolized key exists
  # @param [#to_sym] key the key to test
  # @return [Boolean] whether the key exists
  def key?(key) super(key.to_sym) end
  alias has_key? key?

  # Updates the object with the contents of another Hash object.
  # This method modifies the original SymbolHash object
  #
  # @param [Hash] hash the hash object to copy the values from
  # @return [SymbolHash] self
  def update(hash) hash.each {|k, v| self[k] = v }; self end
  alias merge! update

  # Merges the contents of another hash into a new SymbolHash object
  #
  # @param [Hash] hash the hash of objects to copy
  # @return [SymbolHash] a new SymbolHash containing the merged data
  def merge(hash) dup.merge!(hash) end
end
