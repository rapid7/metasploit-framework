# frozen_string_literal: true
module YARD::CodeObjects
  register_separator NSEP, :namespace
  default_separator NSEP

  # A "namespace" is any object that can store other objects within itself.
  # The two main Ruby objects that can act as namespaces are modules
  # ({ModuleObject}) and classes ({ClassObject}).
  class NamespaceObject < Base
    # @return [Array<String>] a list of ordered group names inside the namespace
    # @since 0.6.0
    attr_accessor :groups

    # The list of objects defined in this namespace
    # @return [Array<Base>] a list of objects
    attr_reader :children

    # A hash containing two keys, class and instance, each containing
    # the attribute name with a { :read, :write } hash for the read and
    # write objects respectively.
    #
    # @example The attributes of an object
    #   >> Registry.at('YARD::Docstring').attributes
    #   => {
    #         :class => { },
    #         :instance => {
    #           :ref_tags => {
    #             :read => #<yardoc method YARD::Docstring#ref_tags>,
    #             :write => nil
    #           },
    #           :object => {
    #             :read => #<yardoc method YARD::Docstring#object>,
    #             :write => #<yardoc method YARD::Docstring#object=>
    #            },
    #            ...
    #         }
    #       }
    # @return [Hash] a list of methods
    attr_reader :attributes

    # A hash containing two keys, :class and :instance, each containing
    # a hash of objects and their alias names.
    # @return [Hash] a list of methods
    attr_reader :aliases

    # Class mixins
    # @return [Array<ModuleObject>] a list of mixins
    attr_reader :class_mixins

    # Instance mixins
    # @return [Array<ModuleObject>] a list of mixins
    attr_reader :instance_mixins

    # Creates a new namespace object inside +namespace+ with +name+.
    # @see Base#initialize
    def initialize(namespace, name, *args, &block)
      @children = CodeObjectList.new(self)
      @class_mixins = CodeObjectList.new(self)
      @instance_mixins = CodeObjectList.new(self)
      @attributes = SymbolHash[:class => SymbolHash.new, :instance => SymbolHash.new]
      @aliases = {}
      @groups = []
      super
    end

    # Only the class attributes
    # @return [Hash] a list of method names and their read/write objects
    # @see #attributes
    def class_attributes
      attributes[:class]
    end

    # Only the instance attributes
    # @return [Hash] a list of method names and their read/write objects
    # @see #attributes
    def instance_attributes
      attributes[:instance]
    end

    # Looks for a child that matches the attributes specified by +opts+.
    #
    # @example Finds a child by name and scope
    #   namespace.child(:name => :to_s, :scope => :instance)
    #   # => #<yardoc method MyClass#to_s>
    # @return [Base, nil] the first matched child object, or nil
    def child(opts = {})
      if !opts.is_a?(Hash)
        children.find {|o| o.name == opts.to_sym }
      else
        opts = SymbolHash[opts]
        children.find do |obj|
          opts.each do |meth, value|
            break false unless value.is_a?(Array) ? value.include?(obj[meth]) : obj[meth] == value
          end
        end
      end
    end

    # Returns all methods that match the attributes specified by +opts+. If
    # no options are provided, returns all methods.
    #
    # @example Finds all private and protected class methods
    #   namespace.meths(:visibility => [:private, :protected], :scope => :class)
    #   # => [#<yardoc method MyClass.privmeth>, #<yardoc method MyClass.protmeth>]
    # @option opts [Array<Symbol>, Symbol] :visibility ([:public, :private,
    #   :protected]) the visibility of the methods to list. Can be an array or
    #   single value.
    # @option opts [Array<Symbol>, Symbol] :scope ([:class, :instance]) the
    #   scope of the methods to list. Can be an array or single value.
    # @option opts [Boolean] :included (true) whether to include mixed in
    #   methods in the list.
    # @return [Array<MethodObject>] a list of method objects
    def meths(opts = {})
      opts = SymbolHash[
        :visibility => [:public, :private, :protected],
        :scope => [:class, :instance],
        :included => true
      ].update(opts)

      opts[:visibility] = [opts[:visibility]].flatten
      opts[:scope] = [opts[:scope]].flatten

      ourmeths = children.select do |o|
        o.is_a?(MethodObject) &&
          opts[:visibility].include?(o.visibility) &&
          opts[:scope].include?(o.scope)
      end

      ourmeths + (opts[:included] ? included_meths(opts) : [])
    end

    # Returns methods included from any mixins that match the attributes
    # specified by +opts+. If no options are specified, returns all included
    # methods.
    #
    # @option opts [Array<Symbol>, Symbol] :visibility ([:public, :private,
    #   :protected]) the visibility of the methods to list. Can be an array or
    #   single value.
    # @option opts [Array<Symbol>, Symbol] :scope ([:class, :instance]) the
    #   scope of the methods to list. Can be an array or single value.
    # @option opts [Boolean] :included (true) whether to include mixed in
    #   methods in the list.
    # @see #meths
    def included_meths(opts = {})
      opts = SymbolHash[:scope => [:instance, :class]].update(opts)
      [opts[:scope]].flatten.map do |scope|
        mixins(scope).inject([]) do |list, mixin|
          next list if mixin.is_a?(Proxy)
          arr = mixin.meths(opts.merge(:scope => :instance)).reject do |o|
            next false if opts[:all]
            child(:name => o.name, :scope => scope) || list.find {|o2| o2.name == o.name }
          end
          arr.map! {|o| ExtendedMethodObject.new(o) } if scope == :class
          list + arr
        end
      end.flatten
    end

    # Returns all constants in the namespace
    #
    # @option opts [Boolean] :included (true) whether or not to include
    #   mixed in constants in list
    # @return [Array<ConstantObject>] a list of constant objects
    def constants(opts = {})
      opts = SymbolHash[:included => true].update(opts)
      consts = children.select {|o| o.is_a? ConstantObject }
      consts + (opts[:included] ? included_constants : [])
    end

    # Returns constants included from any mixins
    # @return [Array<ConstantObject>] a list of constant objects
    def included_constants
      instance_mixins.inject([]) do |list, mixin|
        if mixin.respond_to? :constants
          list += mixin.constants.reject do |o|
            child(:name => o.name) || list.find {|o2| o2.name == o.name }
          end
        else
          list
        end
      end
    end

    # Returns class variables defined in this namespace.
    # @return [Array<ClassVariableObject>] a list of class variable objects
    def cvars
      children.select {|o| o.is_a? ClassVariableObject }
    end

    # Returns for specific scopes. If no scopes are provided, returns all mixins.
    # @param [Array<Symbol>] scopes a list of scopes (:class, :instance) to
    #   return mixins for. If this is empty, all scopes will be returned.
    # @return [Array<ModuleObject>] a list of mixins
    def mixins(*scopes)
      return class_mixins if scopes == [:class]
      return instance_mixins if scopes == [:instance]
      class_mixins | instance_mixins
    end
  end
end
