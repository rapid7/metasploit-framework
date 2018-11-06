module Pry::Config::Behavior
  ASSIGNMENT     = "=".freeze
  NODUP          = [TrueClass, FalseClass, NilClass, Symbol, Numeric, Module, Proc].freeze
  INSPECT_REGEXP = /#{Regexp.escape "default=#<"}/
  ReservedKeyError = Class.new(RuntimeError)

  module Builder
    #
    # @param [Hash] attributes
    #   a hash to initialize an instance of self with.
    #
    # @param [Pry::Config, nil] default
    #   a default, or nil for none.
    #
    # @return [Pry::Config]
    #   returns an instance of self.
    #
    def from_hash(attributes, default = nil)
      new(default).tap do |config|
        attributes.each do |key,value|
          config[key] = Hash === value ? from_hash(value, nil) : value
        end
      end
    end
  end

  def self.included(klass)
    klass.extend(Builder)
  end

  def initialize(default = Pry.config)
    @default = default
    @lookup = {}
    @reserved_keys = methods.map(&:to_s).freeze
  end

  #
  # @return [Pry::Config::Behavior]
  #   returns the default used incase a key isn't found in self.
  #
  def default
    @default
  end

  #
  # @param [String] key
  #   a key (as a String)
  #
  # @return [Object, BasicObject]
  #   returns an object from self or one of its defaults.
  #
  def [](key)
    key = key.to_s
    key?(key) ? @lookup[key] : (@default and @default[key])
  end

  #
  # Add a key and value pair to self.
  #
  # @param [String] key
  #   a key (as a String).
  #
  # @param [Object,BasicObject] value
  #   a value.
  #
  # @raise [Pry::Config::ReservedKeyError]
  #   when 'key' is a reserved key name.
  #
  def []=(key, value)
    key = key.to_s
    if @reserved_keys.include?(key)
      raise ReservedKeyError, "It is not possible to use '#{key}' as a key name, please choose a different key name."
    end
    __push(key,value)
  end

  #
  # Removes a key from self.
  #
  # @param [String] key
  #  a key (as a String)
  #
  # @return [void]
  #
  def forget(key)
    key = key.to_s
    __remove(key)
  end

  #
  # @param [Hash, #to_h, #to_hash] other
  #   a hash to merge into self.
  #
  # @return [void]
  #
  def merge!(other)
    other = __try_convert_to_hash(other)
    raise TypeError, "unable to convert argument into a Hash" unless other
    other.each do |key, value|
      self[key] = value
    end
  end

  #
  # @param [Hash, #to_h, #to_hash] other
  #   a hash to compare against the lookup table of self.
  #
  def ==(other)
    @lookup == __try_convert_to_hash(other)
  end
  alias_method :eql?, :==

  #
  # @param [String] key
  #   a key (as a String)
  #
  # @return [Boolean]
  #   returns true when "key" is a member of self.
  #
  def key?(key)
    key = key.to_s
    @lookup.key?(key)
  end

  #
  # Clear the lookup table of self.
  #
  # @return [void]
  #
  def clear
    @lookup.clear
    true
  end

  #
  # @return [Array<String>]
  #   returns an array of keys in self.
  #
  def keys
    @lookup.keys
  end

  def eager_load!
    default = @default
    while default
      default.memoized_methods.each {|method| self[key] = default.public_send(key)} if default.respond_to?(:memoized_methods)
      default = @default.default
    end
  end

  def last_default
    last = @default
    last = last.default while last and last.default
    last
  end

  #
  # @return [Hash]
  #   returns a duplicate copy of the lookup table used by self.
  #
  def to_hash
    @lookup.dup
  end
  alias_method :to_h, :to_hash

  def inspect
    key_str = keys.map { |key| "'#{key}'" }.join(",")
    "#<#{__clip_inspect(self)} keys=[#{key_str}] default=#{@default.inspect}>"
  end

  def pretty_print(q)
    q.text inspect[1..-1].gsub(INSPECT_REGEXP, "default=<")
  end

  def method_missing(name, *args, &block)
    key = name.to_s
    if key[-1] == ASSIGNMENT
      short_key = key[0..-2]
      self[short_key] = args[0]
    elsif key?(key)
      self[key]
    elsif @default.respond_to?(name)
      value = @default.public_send(name, *args, &block)
      self[key] = __dup(value)
    else
      nil
    end
  end

  def respond_to_missing?(key, include_all=false)
    key = key.to_s.chomp(ASSIGNMENT)
    key?(key) or @default.respond_to?(key) or super(key, include_all)
  end

private
  def __clip_inspect(obj)
    "#{obj.class}:0x%x" % obj.object_id
  end

  def __try_convert_to_hash(obj)
    if Hash === obj
      obj
    elsif obj.respond_to?(:to_h)
      obj.to_h
    elsif obj.respond_to?(:to_hash)
      obj.to_hash
    else
      nil
    end
  end

  def __dup(value)
    if NODUP.any? { |klass| klass === value }
      value
    else
      value.dup
    end
  end

  def __push(key,value)
    unless singleton_class.method_defined? key
      define_singleton_method(key) { self[key] }
      define_singleton_method("#{key}=") { |val| @lookup[key] = val }
    end
    @lookup[key] = value
  end

  def __remove(key)
    @lookup.delete(key)
  end
end
