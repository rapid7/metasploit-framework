require 'rkelly'

#
# The primary class, used to parse and obfuscate Javascript code.
#
class JSObfu

  require_relative 'jsobfu/scope'
  require_relative 'jsobfu/utils'
  require_relative 'jsobfu/ecma_tight'
  require_relative 'jsobfu/hoister'
  require_relative 'jsobfu/obfuscator'
  require_relative 'jsobfu/disable'

  include JSObfu::Disable

  # @return [JSObfu::Scope] the global scope
  attr_reader :scope

  # Saves +code+ for later obfuscation with #obfuscate
  # @param code [#to_s] the code to obfuscate
  # @param opts [Hash] an options hash
  # @option opts [JSObfu::Scope] a pre-existing scope. This is useful for preserving
  #   variable rename maps between separate obfuscations of different scripts.
  def initialize(code=nil, opts={})
    self.code = code
    @scope = opts.fetch(:scope) { Scope.new }
  end

  # Add +str+ to the un-obfuscated code.
  # Calling this method after #obfuscate is undefined
  def <<(str)
    @code << str
  end

  # @return [String] the (possibly obfuscated) code
  def to_s
    @code
  end

  # @return [RKelly::Nodes::SourceElementsNode] the abstract syntax tree
  def ast
    @ast ||= parse
  end

  # Sets the code that this obfuscator will transform
  # @param [String] code
  def code=(code)
    @ast = nil # invalidate any previous parses
    @code = code
  end

  # Parse and obfuscate
  #
  # @param opts [Hash] the options hash
  # @option opts [Boolean] :strip_whitespace removes unnecessary whitespace from
  #   the output code (true)
  # @option opts [Integer] :iterations number of times to run the
  #   obfuscator on this code (1)
  # @option opts [String] :global the global object to rewrite unresolved lookups to.
  #   Depending on the environment, it may be `window`, `global`, or `this`.
  # @option opts [Boolean] :memory_sensitive the execution environment is sensitive
  #   to changes in memory usage (e.g. a heap spray). This disables string transformations
  #   and other "noisy" obfuscation tactics. (false)
  # @option opts [Array<String>] :preserved_identifiers A list of identifiers to NOT obfuscate
  # @return [self]
  def obfuscate(opts={})
    return self if JSObfu.disabled?
    raise ArgumentError.new("code must be present") if @code.nil?

    iterations = opts.fetch(:iterations, 1).to_i
    strip_whitespace = opts.fetch(:strip_whitespace, true)

    iterations.times do |i|
      obfuscator = JSObfu::Obfuscator.new(opts.merge(scope: @scope))
      @code = obfuscator.accept(ast).to_s
      if strip_whitespace
        @code.gsub!(/(^\s+|\s+$)/, '')
        @code.delete!("\n")
        @code.delete!("\r")
      end

      if @renames
        # "patch up" the renames after each iteration
        @renames.merge! (obfuscator.renames)
      else
        # on first iteration, take the renames as-is
        @renames = obfuscator.renames.dup
      end

      unless i == iterations-1
        @scope = Scope.new
        @ast = nil # force a re-parse
      end
    end

    # Enter all of the renames into current scope
    @scope.renames.merge!(@renames || {})

    self
  end

  # Returns the obfuscated name for the variable or function +sym+
  #
  # @param sym [String] the name of the variable or function
  # @return [String] the obfuscated name
  def sym(sym)
    return sym.to_s if @renames.nil?
    @renames[sym.to_s]
  end

protected

  # Generate an Abstract Syntax Tree (#ast) for later obfuscation
  # @return [RKelly::Nodes::SourceElementsNode] the abstract syntax tree
  def parse
    RKelly::Parser.new.parse(@code)
  end

end
