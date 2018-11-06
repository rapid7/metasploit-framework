class Pry

  # This class is responsible for taking a string (identifying a
  # command/class/method/etc) and returning the relevant type of object.
  # For example, if the user looks up "show-source" then  a
  # `Pry::Command` will be returned. Alternatively, if the user passes in "Pry#repl" then
  # a `Pry::Method` object will be returned.
  #
  # The `CodeObject.lookup` method is responsible for 1. figuring out what kind of
  # object the user wants (applying precedence rules in doing so -- i.e methods
  # get precedence over commands with the same name) and 2. Returning
  # the appropriate object. If the user fails to provide a string
  # identifer for the object (i.e they pass in `nil` or "") then the
  # object looked up will be the 'current method' or 'current class'
  # associated with the Binding.
  #
  # TODO: This class is a clusterfuck. We need a much more robust
  # concept of what a "Code Object" really is. Currently
  # commands/classes/candidates/methods and so on just share a very
  # ill-defined interface.
  class CodeObject
    module Helpers
      # we need this helper as some Pry::Method objects can wrap Procs
      # @return [Boolean]
      def real_method_object?
        is_a?(::Method) || is_a?(::UnboundMethod)
      end

      def c_method?
        real_method_object? && source_type == :c
      end

      def module_with_yard_docs?
        is_a?(WrappedModule) && yard_docs?
      end

      def command?
        is_a?(Module) && self <= Pry::Command
      end

      # @return [Boolean] `true` if this module was defined by means of the C API,
      #   `false` if it's a Ruby module.
      # @note If a module defined by C was extended with a lot of methods written
      #   in Ruby, this method would fail.
      def c_module?
        if is_a?(WrappedModule)

          method_locations = wrapped.methods(false).map do |m|
            wrapped.method(m).source_location
          end

          method_locations.concat(wrapped.instance_methods(false).map do |m|
                                    wrapped.instance_method(m).source_location
                                  end)

          c_methods = method_locations.grep(nil).count
          ruby_methods = method_locations.count - c_methods

          c_methods > ruby_methods
        end
      end
    end

    include Pry::Helpers::CommandHelpers

    class << self
      def lookup(str, _pry_, options={})
        co = new(str, _pry_, options)

        co.default_lookup || co.method_or_class_lookup ||
          co.command_lookup || co.empty_lookup
      end
    end

    attr_accessor :str
    attr_accessor :target
    attr_accessor :_pry_
    attr_accessor :super_level

    def initialize(str, _pry_, options={})
      options = {
        :super => 0,
      }.merge!(options)

      @str = str
      @_pry_ = _pry_
      @target = _pry_.current_context
      @super_level = options[:super]
    end

    def command_lookup
      # TODO: just make it so find_command_by_match_or_listing doesn't
      # raise?
      _pry_.commands.find_command_by_match_or_listing(str) rescue nil
    end

    # when no paramter is given (i.e CodeObject.lookup(nil)), then we
    # lookup the 'current object' from the binding.
    def empty_lookup
      return nil if str && !str.empty?

      obj = if internal_binding?(target)
              mod = target_self.is_a?(Module) ? target_self : target_self.class
              Pry::WrappedModule(mod)
            else
              Pry::Method.from_binding(target)
            end

      # respect the super level (i.e user might have specified a
      # --super flag to show-source)
      lookup_super(obj, super_level)
    end

    # lookup variables and constants and `self` that are not modules
    def default_lookup

      # we skip instance methods as we want those to fall through to method_or_class_lookup()
      if safe_to_evaluate?(str) && !looks_like_an_instance_method?(str)
        obj = target.eval(str)

        # restrict to only objects we KNOW for sure support the full API
        # Do NOT support just any object that responds to source_location
        if sourcable_object?(obj)
          Pry::Method(obj)
        elsif !obj.is_a?(Module)
          Pry::WrappedModule(obj.class)
        else
          nil
        end
      end

    rescue Pry::RescuableException
      nil
    end

    def method_or_class_lookup
      obj = case str
            when /\S+\(\)\z/
              Pry::Method.from_str(str.sub(/\(\)\z/, ''),target) || Pry::WrappedModule.from_str(str, target)
            else
              Pry::WrappedModule.from_str(str,target) || Pry::Method.from_str(str, target)
            end

      lookup_super(obj, super_level)
    end

    private

    def sourcable_object?(obj)
      [::Proc, ::Method, ::UnboundMethod].any? { |o| obj.is_a?(o) }
    end

    # Returns true if `str` looks like a method, i.e Klass#method
    # We need to consider this case because method lookups should fall
    # through to the `method_or_class_lookup()` method but a
    # defined?() on a "Klass#method` string will see the `#` as a
    # comment and only evaluate the `Klass` part.
    # @param [String] str
    # @return [Boolean] Whether the string looks like an instance method.
    def looks_like_an_instance_method?(str)
      str =~ /\S#\S/
    end

    # We use this method to decide whether code is safe to eval. Method's are
    # generally not, but everything else is.
    # TODO: is just checking != "method" enough??
    # TODO: see duplication of this method in Pry::WrappedModule
    # @param [String] str The string to lookup
    # @return [Boolean]
    def safe_to_evaluate?(str)
      return true if str.strip == "self"
      return false if str =~ /%/
      kind = target.eval("defined?(#{str})")
      kind =~ /variable|constant/
    end

    def target_self
      target.eval('self')
    end

    # grab the nth (`super_level`) super of `obj
    # @param [Object] obj
    # @param [Fixnum] super_level How far up the super chain to ascend.
    def lookup_super(obj, super_level)
      return nil if !obj

      sup = obj.super(super_level)
      if !sup
        raise Pry::CommandError, "No superclass found for #{obj.wrapped}"
      else
        sup
      end
    end
  end
end
