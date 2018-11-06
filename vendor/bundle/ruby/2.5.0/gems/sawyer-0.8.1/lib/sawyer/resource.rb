module Sawyer
  class Resource
    SPECIAL_METHODS = Set.new(%w(agent rels fields))
    attr_reader :_agent, :_rels, :_fields
    attr_reader :attrs
    include Enumerable

    # Initializes a Resource with the given data.
    #
    # agent - The Sawyer::Agent that made the API request.
    # data  - Hash of key/value properties.
    def initialize(agent, data = {})
      @_agent  = agent
      data, links = agent.parse_links(data)
      @_rels = Relation.from_links(agent, links)
      @_fields = Set.new
      @_metaclass = (class << self; self; end)
      @attrs = {}
      data.each do |key, value|
        @_fields << key
        @attrs[key.to_sym] = process_value(value)
      end
      @_metaclass.send(:attr_accessor, *data.keys)
    end

    # Processes an individual value of this resource.  Hashes get exploded
    # into another Resource, and Arrays get their values processed too.
    #
    # value - An Object value of a Resource's data.
    #
    # Returns an Object to set as the value of a Resource key.
    def process_value(value)
      case value
      when Hash  then self.class.new(@_agent, value)
      when Array then value.map { |v| process_value(v) }
      else value
      end
    end

    # Checks to see if the given key is in this resource.
    #
    # key - A Symbol key.
    #
    # Returns true if the key exists, or false.
    def key?(key)
      @_fields.include? key
    end

    # Allow fields to be retrieved via Hash notation
    #
    # method - key name
    #
    # Returns the value from attrs if exists
    def [](method)
      send(method.to_sym)
    rescue NoMethodError
      nil
    end

    # Allow fields to be set via Hash notation
    #
    # method - key name
    # value - value to set for the attr key
    #
    # Returns - value
    def []=(method, value)
      send("#{method}=", value)
    rescue NoMethodError
      nil
    end

    ATTR_SETTER    = '='.freeze
    ATTR_PREDICATE = '?'.freeze

    # Provides access to a resource's attributes.
    def method_missing(method, *args)
      attr_name, suffix = method.to_s.scan(/([a-z0-9\_]+)(\?|\=)?$/i).first
      if suffix == ATTR_SETTER
        @_metaclass.send(:attr_accessor, attr_name)
        @_fields << attr_name.to_sym
        send(method, args.first)
      elsif attr_name && @_fields.include?(attr_name.to_sym)
        value = @attrs[attr_name.to_sym]
        case suffix
        when nil
          @_metaclass.send(:attr_accessor, attr_name)
          value
        when ATTR_PREDICATE then !!value
        end
      elsif suffix.nil? && SPECIAL_METHODS.include?(attr_name)
        instance_variable_get "@_#{attr_name}"
      elsif attr_name && !@_fields.include?(attr_name.to_sym)
        nil
      else
        super
      end
    end

    # Wire up accessor methods to pull from attrs
    def self.attr_accessor(*attrs)
      attrs.each do |attribute|
        class_eval do
          define_method attribute do
            @attrs[attribute.to_sym]
          end

          define_method "#{attribute}=" do |value|
            @attrs[attribute.to_sym] = value
          end

          define_method "#{attribute}?" do
            !!@attrs[attribute.to_sym]
          end
        end
      end
    end

    def inspect
      to_attrs.respond_to?(:pretty_inspect) ? to_attrs.pretty_inspect : to_attrs.inspect
    end

    def each(&block)
      @attrs.each(&block)
    end

    # private
    def to_yaml_properties
      [:@attrs, :@_fields, :@_rels]
    end

    def to_attrs
      hash = self.attrs.clone
      hash.keys.each do |k|
        if hash[k].is_a?(Sawyer::Resource)
          hash[k] = hash[k].to_attrs
        elsif hash[k].is_a?(Array) && hash[k].all?{|el| el.is_a?(Sawyer::Resource)}
          hash[k] = hash[k].collect{|el| el.to_attrs}
        end
      end
      hash
    end

    alias to_hash to_attrs
    alias to_h to_attrs

    def marshal_dump
      [@attrs, @_fields, @_rels]
    end

    def marshal_load(dumped)
      @attrs, @_fields, @_rels = *dumped.shift(3)
      @_metaclass = (class << self; self; end)
    end
  end
end
