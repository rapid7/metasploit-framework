require 'set'

module Liquid

  parent_object = if defined? BlankObject
    BlankObject
  else
    Object
  end

  # Strainer is the parent class for the filters system.
  # New filters are mixed into the strainer class which is then instanciated for each liquid template render run.
  #
  # One of the strainer's responsibilities is to keep malicious method calls out
  class Strainer < parent_object #:nodoc:
    INTERNAL_METHOD = /^__/
    @@required_methods = Set.new([:__id__, :__send__, :respond_to?, :kind_of?, :extend, :methods, :singleton_methods, :class, :object_id])

    # Ruby 1.9.2 introduces Object#respond_to_missing?, which is invoked by Object#respond_to?
    @@required_methods << :respond_to_missing? if Object.respond_to? :respond_to_missing?

    @@filters = {}

    def initialize(context)
      @context = context
    end

    def self.global_filter(filter)
      raise ArgumentError, "Passed filter is not a module" unless filter.is_a?(Module)
      @@filters[filter.name] = filter
    end

    def self.create(context)
      strainer = Strainer.new(context)
      @@filters.each { |k,m| strainer.extend(m) }
      strainer
    end

    def respond_to?(method, include_private = false)
      method_name = method.to_s
      return false if method_name =~ INTERNAL_METHOD
      return false if @@required_methods.include?(method_name)
      super
    end

    # remove all standard methods from the bucket so circumvent security
    # problems
    instance_methods.each do |m|
      unless @@required_methods.include?(m.to_sym)
        undef_method m
      end
    end
  end
end
