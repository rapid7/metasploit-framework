# frozen_string_literal: true
module YARD::CodeObjects
  register_separator NSEP, :class

  # A ClassObject represents a Ruby class in source code. It is a {ModuleObject}
  # with extra inheritance semantics through the superclass.
  class ClassObject < NamespaceObject
    # The {ClassObject} that this class object inherits from in Ruby source.
    # @return [ClassObject] a class object that is the superclass of this one
    attr_reader :superclass

    # Creates a new class object in +namespace+ with +name+
    #
    # @see Base.new
    def initialize(namespace, name, *args, &block)
      super

      if is_exception?
        self.superclass ||= "::Exception" unless P(namespace, name) == P(:Exception)
      else
        case P(namespace, name).path
        when "BasicObject"
          nil
        when "Object"
          self.superclass ||= "::BasicObject"
        else
          self.superclass ||= "::Object"
        end
      end
    end

    # Whether or not the class is a Ruby Exception
    #
    # @return [Boolean] whether the object represents a Ruby exception
    def is_exception?
      inheritance_tree.reverse.any? {|o| BUILTIN_EXCEPTIONS_HASH.key? o.path }
    end

    # Returns the inheritance tree of the object including self.
    #
    # @param [Boolean] include_mods whether or not to include mixins in the
    #   inheritance tree.
    # @return [Array<NamespaceObject>] the list of code objects that make up
    #   the inheritance tree.
    def inheritance_tree(include_mods = false)
      list = (include_mods ? mixins(:instance, :class) : [])
      if superclass.is_a?(Proxy) || superclass.respond_to?(:inheritance_tree)
        list += [superclass] unless superclass == P(:Object) || superclass == P(:BasicObject)
      end
      [self] + list.map do |m|
        next m if m == self
        next m unless m.respond_to?(:inheritance_tree)
        m.inheritance_tree(include_mods)
      end.flatten.uniq
    end

    # Returns the list of methods matching the options hash. Returns
    # all methods if hash is empty.
    #
    # @param [Hash] opts the options hash to match
    # @option opts [Boolean] :inherited (true) whether inherited methods should be
    #   included in the list
    # @option opts [Boolean] :included (true) whether mixed in methods should be
    #   included in the list
    # @return [Array<MethodObject>] the list of methods that matched
    def meths(opts = {})
      opts = SymbolHash[:inherited => true].update(opts)
      list = super(opts)
      list += inherited_meths(opts).reject do |o|
        next(false) if opts[:all]
        list.find {|o2| o2.name == o.name && o2.scope == o.scope }
      end if opts[:inherited]
      list
    end

    # Returns only the methods that were inherited.
    #
    # @return [Array<MethodObject>] the list of inherited method objects
    def inherited_meths(opts = {})
      inheritance_tree[1..-1].inject([]) do |list, superclass|
        if superclass.is_a?(Proxy)
          list
        else
          list += superclass.meths(opts).reject do |o|
            next(false) if opts[:all]
            child(:name => o.name, :scope => o.scope) ||
              list.find {|o2| o2.name == o.name && o2.scope == o.scope }
          end
        end
      end
    end

    # Returns the list of constants matching the options hash.
    #
    # @param [Hash] opts the options hash to match
    # @option opts [Boolean] :inherited (true) whether inherited constant should be
    #   included in the list
    # @option opts [Boolean] :included (true) whether mixed in constant should be
    #   included in the list
    # @return [Array<ConstantObject>] the list of constant that matched
    def constants(opts = {})
      opts = SymbolHash[:inherited => true].update(opts)
      super(opts) + (opts[:inherited] ? inherited_constants : [])
    end

    # Returns only the constants that were inherited.
    #
    # @return [Array<ConstantObject>] the list of inherited constant objects
    def inherited_constants
      inheritance_tree[1..-1].inject([]) do |list, superclass|
        if superclass.is_a?(Proxy)
          list
        else
          list += superclass.constants.reject do |o|
            child(:name => o.name) || list.find {|o2| o2.name == o.name }
          end
        end
      end
    end

    # Sets the superclass of the object
    #
    # @param [Base, Proxy, String, Symbol, nil] object the superclass value
    # @return [void]
    def superclass=(object)
      case object
      when Base, Proxy, NilClass
        @superclass = object
      when String, Symbol
        @superclass = Proxy.new(namespace, object)
      else
        raise ArgumentError, "superclass must be CodeObject, Proxy, String or Symbol"
      end

      if name == @superclass.name && namespace != YARD::Registry.root && !object.is_a?(Base)
        @superclass = Proxy.new(namespace.namespace, object)
      end

      if @superclass == self
        msg = "superclass #{@superclass.inspect} cannot be the same as the declared class #{inspect}"
        @superclass = P("::Object")
        raise ArgumentError, msg
      end
    end
  end
end
