require_relative 'utils'
require 'set'

# A single Javascript scope, used as a key-value store
# to maintain uniqueness of members in generated closures.
# For speed this class is implemented as a subclass of Hash.
class JSObfu::Scope < Hash

  # these keywords should never be used as a random var name
  # source: https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Reserved_Words
  RESERVED_KEYWORDS = %w(
    break case catch continue debugger default delete do else finally
    for function if in instanceof new return switch this throw try
    typeof var void while with class enum export extends import super
    implements interface let package private protected public static yield
    const let
  )

  # these vars should not be shadowed as they in the exploit code,
  # and generating them would cause problems.
  BUILTIN_VARS = %w(
    String window unescape location chrome document navigator location
    frames ActiveXObject XMLHttpRequest Function eval Object Math CSS
    parent opener event frameElement Error TypeError setTimeout setInterval
    top arguments Array Date
  )

  # @return [JSObfu::Scope] parent that spawned this scope
  attr_accessor :parent

  # @return [Hash] mapping old var names to random ones
  attr_accessor :renames

  # @return [Number] the 0-indexed depth of the scope stack
  attr_accessor :depth

  # @param [Hash] opts the options hash
  # @option opts [Rex::Exploitation::JSObfu::Scope] :parent an optional parent scope,
  #   sometimes necessary to prevent needless var shadowing
  # @option opts [Integer] :min_len minimum length of the var names
  def initialize(opts={})
    @parent         = opts[:parent]
    @first_char_set = opts[:first_char_set] || [*'A'..'Z']+[*'a'..'z']+['_', '$']
    @char_set       = opts[:first_char_set] || @first_char_set + [*'0'..'9']
    @min_len        = opts[:min_len] || 1
    @renames        = {}
    @depth          = -1
  end

  # Generates a unique, "safe" random variable
  # @return [String] a unique random var name that is not a reserved keyword
  def random_var_name
    len = @min_len
    loop do
      text = random_string(len)
      unless has_key?(text) or
        RESERVED_KEYWORDS.include?(text) or
        BUILTIN_VARS.include?(text)

        self[text] = nil

        return text
      end
      len += 1
    end
  end
  # Re-maps your +var_name+ to a unique, random
  # names in the current scope
  #
  # @param var_name [String] the name you want to replace. This
  #   name will be remembered in the #renames hash
  # @param opts [Hash] the options hash
  # @option opts [Boolean] :generate if the variable was not
  #   explicitly renamed before, in this scope or any parent
  #   scope, generate a new random name
  #
  # @return [String] the randomly generated replacement name
  # @return nil if generate=false and +var_name+ was not already replaced
  def rename_var(var_name, opts={})
    return var_name if BUILTIN_VARS.include?(var_name)

    generate = opts.fetch(:generate, true)
    unresolved = opts.fetch(:unresolved, [])
    renamed = @renames[var_name]

    if renamed.nil? and parent
      renamed = parent.rename_var(var_name, :generate => false)
    end

    if renamed.nil? and generate
      @renames[var_name] = random_var_name
      renamed = @renames[var_name]
    end

    #puts "Mapped #{var_name} => #{renamed}" if renamed

    renamed
  end

  # @return [Boolean] scope has members
  def empty?
    self.keys.empty? and (parent.nil? or parent.empty?)
  end

  # @return [Boolean] scope has no parent
  def top?
    parent.nil?
  end

  def top
    p = self
    p = p.parent until p.parent.nil?
    p
  end

  # Check if we've used this var before. This will also check any
  # attached parent scopes (and their parents, recursively)
  #
  # @return [Boolean] whether var is in scope
  def has_key?(key)
    super or (parent and parent.has_key?(key))
  end

  # replaces this Scope in the "parent" chain with a copy,
  # empties current scope, and returns. Essentially an in-place
  # push operation
  def push!
    @depth += 1
    replacement = dup
    replacement.parent = @parent
    replacement.renames = @renames
    @renames = {}
    @parent = replacement
    clear
  end

  # "Consumes" the parent and replaces self with it
  def pop!(opts={})
    retain = opts.fetch(:retain, false)
    @depth -= 1
    clear unless retain
    if @parent
      merge! @parent
      @renames = @parent.renames
      @parent = @parent.parent
    end
  end

  # @return [String] a random string that can be used as a var
  def random_string(len)
    @first_char_set.sample + (len-1).times.map { @char_set.sample }.join
  end

end
