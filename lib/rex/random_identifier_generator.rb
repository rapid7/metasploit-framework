
# A quick way to produce unique random strings that follow the rules of
# identifiers, i.e., begin with a letter and contain only alphanumeric
# characters and underscore.
#
# The advantage of using this class over, say, {Rex::Text.rand_text_alpha}
# each time you need a new identifier is that it ensures you don't have
# collisions.
#
# @example
#   vars = Rex::RandomIdentifierGenerator.new
#   asp_code = <<-END_CODE
#     Sub #{vars[:func]}()
#       Dim #{vars[:fso]}
#       Set #{vars[:fso]} = CreateObject("Scripting.FileSystemObject")
#       ...
#     End Sub
#     #{vars[:func]}
#   END_CODE
#
class Rex::RandomIdentifierGenerator

  # Raised when a RandomIdentifierGenerator cannot create any more
  # identifiers without collisions.
  class ExhaustedSpaceError < StandardError; end

  # Default options
  DefaultOpts = {
    # Arbitrary
    :max_length => 12,
    :min_length => 3,
    # This should be pretty universal for identifier rules
    :char_set => Rex::Text::AlphaNumeric+"_",
    :first_char_set => Rex::Text::LowerAlpha
  }

  # @param opts [Hash] Options, see {DefaultOpts} for default values
  # @option opts :max_length [Fixnum]
  # @option opts :min_length [Fixnum]
  # @option opts :char_set [String]
  def initialize(opts={})
    # Holds all identifiers.
    @value_by_name = {}
    # Inverse of value_by_name so we can ensure uniqueness without
    # having to search through the whole list of values
    @name_by_value = {}

    @opts = DefaultOpts.merge(opts)
    if @opts[:min_length] < 1 || @opts[:max_length] < 1 || @opts[:max_length] < @opts[:min_length]
      raise ArgumentError, "Invalid length options"
    end

    # This is really just the maximum number of shortest names. This
    # will still be a pretty big number most of the time, so don't
    # bother calculating the real one, which will potentially be
    # expensive, since we're talking about a 36-digit decimal number to
    # represent the total possibilities for the range of 10- to
    # 20-character identifiers.
    #
    # 26 because the first char is lowercase alpha, (min_length - 1) and
    # not just min_length because it includes that first alpha char.
    @max_permutations = 26 * (@opts[:char_set].length ** (@opts[:min_length]-1))
    # The real number of permutations could be calculated thusly:
    #((@opts[:min_length]-1) .. (@opts[:max_length]-1)).reduce(0) { |a, e|
    #	a + (26 * @opts[:char_set].length ** e)
    #}
  end

  # Returns the @value_by_name hash
  #
  # @return [Hash]
  def to_h
    return @value_by_name
  end

  # Return a unique random identifier for +name+, generating a new one
  # if necessary.
  #
  # @param name [Symbol] A descriptive, intention-revealing name for an
  #   identifier. This is what you would normally call the variable if
  #   you weren't generating it.
  # @return [String]
  def get(name)
    return @value_by_name[name] if @value_by_name[name]

    @value_by_name[name] = generate
    @name_by_value[@value_by_name[name]] = name

    @value_by_name[name]
  end
  alias [] get
  alias init_var get

  # Add a new identifier. Its name will be checked for uniqueness among
  # previously-generated names.
  #
  # @note This should be called *before* any calls to {#get} to avoid
  #   potential collisions. If you do hit a collision, this method will
  #   raise.
  #
  # @param name (see #get)
  # @param value [String] The identifier that will be returned by
  #   subsequent calls to {#get} with the sane +name+.
  # @raise RuntimeError if +value+ already exists
  # @return [void]
  def store(name, value)

    case @name_by_value[value]
    when name
      # we already have this value and it is associated with this name
      # nothing to do here
    when nil
      # don't have this value yet, so go ahead and just insert
      @value_by_name[name] = value
      @name_by_value[value] = name
    else
      # then the caller is trying to insert a duplicate
      raise RuntimeError, "Value is not unique!"
    end

    self
  end

  # Create a random string that satisfies most languages' requirements
  # for identifiers. In particular, with a default configuration, the
  # first character will always be lowercase alpha (unless modified by a
  # block), and the whole thing will contain only a-zA-Z0-9_ characters.
  #
  # If called with a block, the block will be given the identifier before
  # uniqueness checks. The block's return value will be the new
  # identifier. Note that the block may be called multiple times if it
  # returns a non-unique value.
  #
  # @note Calling this method with a block that returns only values that
  #   this generator already contains will result in an infinite loop.
  #
  # @example
  #   rig = Rex::RandomIdentifierGenerator.new
  #   const = rig.generate { |val| val.capitalize }
  #   rig.insert(:SOME_CONSTANT, const)
  #   ruby_code = <<-EOC
  #     #{rig[:SOME_CONSTANT]} = %q^generated ruby constant^
  #     def #{rig[:my_method]}; ...; end
  #   EOC
  #
  # @param len [Fixnum] Avoid setting this unless a specific size is
  #   necessary. Default is random within range of min .. max
  # @return [String] A string that matches <tt>[a-z][a-zA-Z0-9_]*</tt>
  # @yield [String] The identifier before uniqueness checks. This allows
  #   you to modify the value and still avoid collisions.
  def generate(len=nil)
    raise ArgumentError, "len must be positive integer" if len && len < 1
    raise ExhaustedSpaceError if @value_by_name.length >= @max_permutations

    # pick a random length within the limits
    len ||= rand(@opts[:min_length] .. (@opts[:max_length]))

    ident = ""

    # XXX: Infinite loop if block returns only values we've already
    # generated.
    loop do
      ident  = Rex::Text.rand_base(1, "", @opts[:first_char_set])
      ident << Rex::Text.rand_base(len-1, "", @opts[:char_set])
      if block_given?
        ident = yield ident
      end
      # Try to make another one if it collides with a previously
      # generated one.
      break unless @name_by_value.key?(ident)
    end

    ident
  end

end
