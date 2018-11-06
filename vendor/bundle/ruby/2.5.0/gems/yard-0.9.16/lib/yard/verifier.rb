# frozen_string_literal: true
module YARD
  # Similar to a Proc, but runs a set of Ruby expressions using a small
  # DSL to make tag lookups easier.
  #
  # The syntax is as follows:
  # * All syntax is Ruby compatible
  # * +object+ (+o+ for short) exist to access the object being verified
  # * +@TAGNAME+ is translated into +object.tag('TAGNAME')+
  # * +@@TAGNAME+ is translated into +object.tags('TAGNAME')+
  # * +object+ can be omitted as target for method calls (it is implied)
  #
  # @example Create a verifier to check for objects that don't have @private tags
  #   verifier = Verifier.new('!@private')
  #   verifier.call(object) # => true (no @private tag)
  # @example Create a verifier to find any return tag with an empty description
  #   Verifier.new('@return.text.empty?')
  #   # Equivalent to:
  #   Verifier.new('object.tag(:return).text.empty?')
  # @example Check if there are any @param tags
  #   Verifier.new('@@param.empty?')
  #   # Equivalent to:
  #   Verifier.new('object.tags(:param).empty?')
  # @example Using +object+ or +o+ to look up object attributes directly
  #   Verifier.new('object.docstring == "hello world"')
  #   # Equivalent to:
  #   Verifier.new('o.docstring == "hello world"')
  # @example Without using +object+ or +o+
  #   Verifier.new('tag(:return).size == 1 || has_tag?(:author)')
  # @example Specifying multiple expressions
  #   Verifier.new('@return', '@param', '@yield')
  #   # Equivalent to:
  #   Verifier.new('@return && @param && @yield')
  class Verifier
    # @return [Array<String>] a list of all expressions the verifier checks for
    # @since 0.5.6
    attr_reader :expressions

    def expressions=(value)
      @expressions = value
      create_method_from_expressions
    end

    # Creates a verifier from a set of expressions
    #
    # @param [Array<String>] expressions a list of Ruby expressions to
    #   parse.
    def initialize(*expressions)
      @expressions = []
      add_expressions(*expressions)
    end

    # Adds a set of expressions and recompiles the verifier
    #
    # @param [Array<String>] expressions a list of expressions
    # @return [void]
    # @since 0.5.6
    def add_expressions(*expressions)
      self.expressions += expressions.flatten
    end

    # Passes any method calls to the object from the {#call}
    def method_missing(sym, *args, &block)
      if object.respond_to?(sym)
        object.send(sym, *args, &block)
      else
        super
      end
    end

    # Tests the expressions on the object.
    #
    # @note If the object is a {CodeObjects::Proxy} the result will always be true.
    # @param [CodeObjects::Base] object the object to verify
    # @return [Boolean] the result of the expressions
    def call(object)
      return true if object.is_a?(CodeObjects::Proxy)
      modify_nilclass
      @object = object
      retval = __execute ? true : false
      unmodify_nilclass
      retval
    end

    # Runs a list of objects against the verifier and returns the subset
    # of verified objects.
    #
    # @param [Array<CodeObjects::Base>] list a list of code objects
    # @return [Array<CodeObjects::Base>] a list of code objects that match
    #   the verifier.
    def run(list)
      list.reject {|item| call(item).is_a?(FalseClass) }
    end

    protected

    # @return [CodeObjects::Base] the current object being tested
    attr_reader :object
    alias o object

    private

    # @private
    NILCLASS_METHODS = [:type, :method_missing]

    # Modifies nil to not throw NoMethodErrors. This allows
    # syntax like object.tag(:return).text to work if the #tag
    # call returns nil, which means users don't need to perform
    # stringent nil checking
    #
    # @return [void]
    def modify_nilclass
      NILCLASS_METHODS.each do |meth|
        NilClass.send(:define_method, meth) {|*args| }
      end
    end

    # Returns the state of NilClass back to normal
    # @return [void]
    def unmodify_nilclass
      NILCLASS_METHODS.each do |meth|
        next unless nil.respond_to?(meth)
        NilClass.send(:remove_method, meth)
      end
    end

    # Creates the +__execute+ method by evaluating the expressions
    # as Ruby code
    # @return [void]
    def create_method_from_expressions
      expr = expressions.map {|e| "(#{parse_expression(e)})" }.join(" && ")

      instance_eval(<<-eof, __FILE__, __LINE__ + 1)
        begin; undef __execute; rescue NameError; end
        def __execute; #{expr}; end
      eof
    end

    # Parses a single expression, handling some of the DSL syntax.
    #
    # The syntax "@tag" should be turned into object.tag(:tag),
    # and "@@tag" should be turned into object.tags(:tag)
    #
    # @return [String] the parsed expression
    def parse_expression(expr)
      expr = expr.gsub(/@@(?:(\w+)|\{([\w\.]+)\})/, 'object.tags("\1\2")')
      expr = expr.gsub(/@(?:(\w+)|\{([\w\.]+)\})/, 'object.tag("\1\2")')
      expr
    end
  end
end
