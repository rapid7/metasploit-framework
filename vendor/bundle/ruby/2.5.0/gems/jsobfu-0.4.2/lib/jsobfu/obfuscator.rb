require_relative 'ecma_tight'

class JSObfu::Obfuscator < JSObfu::ECMANoWhitespaceVisitor

  # @return [JSObfu::Scope] the scope maintained while walking the ast
  attr_reader :scope

  # @return [Hash] of original var/fn names to our new random neames
  attr_reader :renames

  # @return [String] the global object in this JS environment
  attr_reader :global

  # unresolved lookups are rewritten as property lookups on the global object
  DEFAULT_GLOBAL  = 'window'

  # some "global" functions are actually keywords, like void(5)
  BUILTIN_METHODS = ['void']

  # @param opts [Hash] the options hash
  # @option opts [JSObfu::Scope] :scope the optional scope to save vars to
  # @option opts [String] :global the global object to rewrite unresolved lookups to.
  #   Depending on the environment, it may be `window`, `global`, or `this`.
  # @option opts [Boolean] :memory_sensitive the execution environment is sensitive
  #   to changes in memory usage (e.g. a heap spray). This disables string transformations
  #   and other "noisy" obfuscation tactics. (false)
  def initialize(opts={})
    @scope = opts.fetch(:scope) { JSObfu::Scope.new }
    @global = opts.fetch(:global, DEFAULT_GLOBAL).to_s
    @memory_sensitive = !!opts.fetch(:memory_sensitive, false)
    @preserved_identifiers = opts.fetch(:preserved_identifiers, [])
    @renames = {}
    super()
  end

  # Maintains a stack of closures that we have visited. This method is called
  # everytime we visit a nested function.
  #
  # Javascript is functionally-scoped, so a function(){} creates its own
  # unique closure. When resolving variables, Javascript looks "up" the
  # closure stack, ending up as a property lookup in the global scope
  # (available as `window` in all browsers)
  #
  # This is changed in newer ES versions, where a `let` keyword has been
  # introduced, which has regular C-style block scoping. We'll ignore this
  # feature since it is not yet widely used.
  def visit_SourceElementsNode(o)
    scope.push!

    hoister = JSObfu::Hoister.new(parent_scope: scope)
    o.value.each { |x| hoister.accept(x) }

    hoister.scope.keys.each do |key|
      unless @preserved_identifiers.include?(key)
        rename_var(key)
      end
    end

    ret = super

    # maintain a single top-level scope
    scope.pop!(retain: scope.depth == 0)

    ret
  end

  def visit_FunctionDeclNode(o)
    o.value = if o.value and o.value.length > 0
      unless @preserved_identifiers.include?(o.value)
        JSObfu::Utils::random_var_encoding(scope.rename_var(o.value))
      end
    else
      if rand(3) != 0
        JSObfu::Utils::random_var_encoding(scope.random_var_name)
      end
    end

    super
  end

  def visit_FunctionExprNode(o)
    if o.value != 'function' && !@preserved_identifiers.include?(o.value)
      o.value = JSObfu::Utils::random_var_encoding(rename_var(o.value))
    end

    super
  end

  # Called whenever a variable is declared.
  def visit_VarDeclNode(o)
    unless @preserved_identifiers.include?(o.name)
      o.name = JSObfu::Utils::random_var_encoding(rename_var(o.name))
    end

    super
  end

  # Called whenever a variable is referred to (not declared).
  #
  # If the variable was never added to scope, it is assumed to be a global
  # object (like "document"), and hence will not be obfuscated.
  #
  def visit_ResolveNode(o)
    if is_builtin_method?(o.value)
      return super
    end

    new_val = rename_var(o.value, :generate => false)

    if new_val
      o.value = JSObfu::Utils::random_var_encoding(new_val)
      super
    else
      if @memory_sensitive || o.value.to_s == global.to_s || @preserved_identifiers.include?(o.value.to_s)
        # if the ref is the global object, don't obfuscate it on itself. This helps
        # "shimmed" globals (like `window=this` at the top of the script) work reliably.
        super
      else
        # A global is used, at least obfuscate the lookup
        "#{global}[#{JSObfu::Utils::transform_string(o.value, scope, :quotes => false)}]"
      end
    end
  end

  # Called on a dot lookup, like X.Y
  def visit_DotAccessorNode(o)
    if @memory_sensitive || @preserved_identifiers.include?(o.accessor)
      super
    else
      obf_str = JSObfu::Utils::transform_string(o.accessor, scope, :quotes => false)
      "#{o.value.accept(self)}[(#{obf_str})]"
    end
  end

  # Called when a parameter is declared. "Shadowed" parameters in the original
  # source are preserved - the randomized name is "shadowed" from the outer scope.
  def visit_ParameterNode(o)
    unless @preserved_identifiers.include?(o.value)
      o.value = JSObfu::Utils::random_var_encoding(rename_var(o.value))
    end

    super
  end

  # A property node in an object "{}"
  def visit_PropertyNode(o)
    # if it is a non-alphanumeric property, obfuscate the string's bytes
    unless @memory_sensitive || @preserved_identifiers.include?(o.name)
      if o.name =~ /^[a-zA-Z_][a-zA-Z0-9_]*$/
         o.instance_variable_set :@name, '"'+JSObfu::Utils::random_string_encoding(o.name)+'"'
      end
    end

    super
  end

  def visit_NumberNode(o)
    unless @memory_sensitive
      o.value = JSObfu::Utils::transform_number(o.value)
    end

    super
  end

  def visit_StringNode(o)
    unless @memory_sensitive
      o.value = JSObfu::Utils::transform_string(o.value, scope)
    end

    super
  end

  def visit_TryNode(o)
    if o.catch_block
      unless @preserved_identifiers.include?(o.catch_var)
        o.instance_variable_set :@catch_var, rename_var(o.catch_var)
      end
    end
    super
  end

  protected

  # Assigns the var +var_name+ a new obfuscated name
  def rename_var(var_name, opts={})
    @renames[var_name] = scope.rename_var(var_name, opts)
  end

  def is_builtin_method?(method)
    BUILTIN_METHODS.include?(method)
  end

end
