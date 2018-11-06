require 'pry/helpers/documentation_helpers'

class Pry
  class << self
    # If the given object is a `Pry::Method`, return it unaltered. If it's
    # anything else, return it wrapped in a `Pry::Method` instance.
    def Method(obj)
      if obj.is_a? Pry::Method
        obj
      else
        Pry::Method.new(obj)
      end
    end
  end

  # This class wraps the normal `Method` and `UnboundMethod` classes
  # to provide extra functionality useful to Pry.
  class Method
    require 'pry/method/weird_method_locator'
    require 'pry/method/disowned'
    require 'pry/method/patcher'

    extend Helpers::BaseHelpers
    include Helpers::BaseHelpers
    include Helpers::DocumentationHelpers
    include CodeObject::Helpers

    class << self
      # Given a string representing a method name and optionally a binding to
      # search in, find and return the requested method wrapped in a `Pry::Method`
      # instance.
      #
      # @param [String] name The name of the method to retrieve.
      # @param [Binding] target The context in which to search for the method.
      # @param [Hash] options
      # @option options [Boolean] :instance Look for an instance method if `name` doesn't
      #   contain any context.
      # @option options [Boolean] :methods Look for a bound/singleton method if `name` doesn't
      #   contain any context.
      # @return [Pry::Method, nil] A `Pry::Method` instance containing the requested
      #   method, or `nil` if name is `nil` or no method could be located matching the parameters.
      def from_str(name, target=TOPLEVEL_BINDING, options={})
        if name.nil?
          nil
        elsif name.to_s =~ /(.+)\#(\S+)\Z/
          context, meth_name = $1, $2
          from_module(target.eval(context), meth_name, target)
        elsif name.to_s =~ /(.+)(\[\])\Z/
          context, meth_name = $1, $2
          from_obj(target.eval(context), meth_name, target)
        elsif name.to_s =~ /(.+)(\.|::)(\S+)\Z/
          context, meth_name = $1, $3
          from_obj(target.eval(context), meth_name, target)
        elsif options[:instance]
          from_module(target.eval("self"), name, target)
        elsif options[:methods]
          from_obj(target.eval("self"), name, target)
        else
          from_str(name, target, :instance => true) or
            from_str(name, target, :methods => true)
        end

      rescue Pry::RescuableException
        nil
      end

      # Given a `Binding`, try to extract the `::Method` it originated from and
      # use it to instantiate a `Pry::Method`. Return `nil` if this isn't
      # possible.
      #
      # @param [Binding] b
      # @return [Pry::Method, nil]
      #
      def from_binding(b)
        meth_name = b.eval('::Kernel.__method__')
        if [:__script__, nil].include?(meth_name)
          nil
        else
          method = begin
                     if Object === b.eval('self')
                       new(Kernel.instance_method(:method).bind(b.eval("self")).call(meth_name))
                     else
                       new(b.eval('class << self; self; end.instance_method(::Kernel.__method__).bind(self)'))
                     end
                   rescue NameError, NoMethodError
                     Disowned.new(b.eval('self'), meth_name.to_s)
                   end

          if WeirdMethodLocator.weird_method?(method, b)
            WeirdMethodLocator.new(method, b).get_method || method
          else
            method
          end
        end
      end

      # In order to support 2.0 Refinements we need to look up methods
      # inside the relevant Binding.
      # @param [Object] obj The owner/receiver of the method.
      # @param [Symbol] method_name The name of the method.
      # @param [Symbol] method_type The type of method: :method or :instance_method
      # @param [Binding] target The binding where the method is looked up.
      # @return [Method, UnboundMethod] The 'refined' method object.
      def lookup_method_via_binding(obj, method_name, method_type, target=TOPLEVEL_BINDING)
        Pry.current[:obj] = obj
        Pry.current[:name] = method_name
        receiver = obj.is_a?(Module) ? "Module" : "Kernel"
        target.eval("::#{receiver}.instance_method(:#{method_type}).bind(Pry.current[:obj]).call(Pry.current[:name])")
      ensure
        Pry.current[:obj] = Pry.current[:name] = nil
      end

      # Given a `Class` or `Module` and the name of a method, try to
      # instantiate a `Pry::Method` containing the instance method of
      # that name. Return `nil` if no such method exists.
      #
      # @param [Class, Module] klass
      # @param [String] name
      # @param [Binding] target The binding where the method is looked up.
      # @return [Pry::Method, nil]
      def from_class(klass, name, target=TOPLEVEL_BINDING)
        new(lookup_method_via_binding(klass, name, :instance_method, target)) rescue nil
      end
      alias from_module from_class

      # Given an object and the name of a method, try to instantiate
      # a `Pry::Method` containing the method of that name bound to
      # that object. Return `nil` if no such method exists.
      #
      # @param [Object] obj
      # @param [String] name
      # @param [Binding] target The binding where the method is looked up.
      # @return [Pry::Method, nil]
      def from_obj(obj, name, target=TOPLEVEL_BINDING)
        new(lookup_method_via_binding(obj, name, :method, target)) rescue nil
      end

      # Get all of the instance methods of a `Class` or `Module`
      # @param [Class,Module] klass
      # @param [Boolean] include_super Whether to include methods from ancestors.
      # @return [Array[Pry::Method]]
      def all_from_class(klass, include_super=true)
        %w(public protected private).flat_map do |visibility|
          safe_send(klass, :"#{visibility}_instance_methods", include_super).map do |method_name|
            new(safe_send(klass, :instance_method, method_name), :visibility => visibility.to_sym)
          end
        end
      end

      #
      # Get all of the methods on an `Object`
      #
      # @param [Object] obj
      #
      # @param [Boolean] include_super
      #   indicates whether or not to include methods from ancestors.
      #
      # @return [Array[Pry::Method]]
      #
      def all_from_obj(obj, include_super=true)
        all_from_class(singleton_class_of(obj), include_super)
      end

      #
      # @deprecated
      #  please use {all_from_obj} instead.
      #  the `method_type` argument is ignored.
      #
      def all_from_common(obj, method_type = nil, include_super=true)
        all_from_obj(obj, include_super)
      end

      # Get every `Class` and `Module`, in order, that will be checked when looking
      # for an instance method to call on this object.
      # @param [Object] obj
      # @return [Array[Class, Module]]
      def resolution_order(obj)
        if Class === obj
          singleton_class_resolution_order(obj) + instance_resolution_order(Class)
        else
          klass = singleton_class_of(obj) rescue obj.class
          instance_resolution_order(klass)
        end
      end

      # Get every `Class` and `Module`, in order, that will be checked when looking
      # for methods on instances of the given `Class` or `Module`.
      # This does not treat singleton classes of classes specially.
      # @param [Class, Module] klass
      # @return [Array[Class, Module]]
      def instance_resolution_order(klass)
        # include klass in case it is a singleton class,
        ([klass] + Pry::Method.safe_send(klass, :ancestors)).uniq
      end

      def method_definition?(name, definition_line)
        singleton_method_definition?(name, definition_line) ||
          instance_method_definition?(name, definition_line)
      end

      def singleton_method_definition?(name, definition_line)
        /^define_singleton_method\(?\s*[:\"\']#{Regexp.escape(name)}|^def\s*self\.#{Regexp.escape(name)}/ =~ definition_line.strip
      end

      def instance_method_definition?(name, definition_line)
        /^define_method\(?\s*[:\"\']#{Regexp.escape(name)}|^def\s*#{Regexp.escape(name)}/ =~ definition_line.strip
      end

      # Get the singleton classes of superclasses that could define methods on
      # the given class object, and any modules they include.
      # If a module is included at multiple points in the ancestry, only
      # the lowest copy will be returned.
      def singleton_class_resolution_order(klass)
        ancestors = Pry::Method.safe_send(klass, :ancestors)
        resolution_order = ancestors.grep(Class).flat_map do |anc|
          [singleton_class_of(anc), *singleton_class_of(anc).included_modules]
        end

        resolution_order.reverse.uniq.reverse - Class.included_modules
      end

      def singleton_class_of(obj)
        begin
          class << obj; self; end
        rescue TypeError # can't define singleton. Fixnum, Symbol, Float, ...
          obj.class
        end
      end
    end

    # A new instance of `Pry::Method` wrapping the given `::Method`, `UnboundMethod`, or `Proc`.
    #
    # @param [::Method, UnboundMethod, Proc] method
    # @param [Hash] known_info Can be used to pre-cache expensive to compute stuff.
    # @return [Pry::Method]
    def initialize(method, known_info={})
      @method = method
      @visibility = known_info[:visibility]
    end

    # Get the name of the method as a String, regardless of the underlying Method#name type.
    # @return [String]
    def name
      @method.name.to_s
    end

    # Get the owner of the method as a Pry::Module
    # @return [Pry::Module]
    def wrapped_owner
      @wrapped_owner ||= Pry::WrappedModule.new(owner)
    end

    # Get underlying object wrapped by this Pry::Method instance
    # @return [Method, UnboundMethod, Proc]
    def wrapped
      @method
    end

    # Is the method undefined? (aka `Disowned`)
    # @return [Boolean] false
    def undefined?
      false
    end

    # Get the name of the method including the class on which it was defined.
    # @example
    #   method(:puts).method_name
    #   => "Kernel.puts"
    # @return [String]
    def name_with_owner
      "#{wrapped_owner.method_prefix}#{name}"
    end

    # @return [String, nil] The source code of the method, or `nil` if it's unavailable.
    def source
      @source ||= case source_type
                  when :c
                    c_source
                  when :ruby
                    ruby_source
                  end
    end

    # Update the live copy of the method's source.
    def redefine(source)
      Patcher.new(self).patch_in_ram source
      Pry::Method(owner.instance_method(name))
    end

    # Can we get the source code for this method?
    # @return [Boolean]
    def source?
      !!source
    rescue MethodSource::SourceNotFoundError
      false
    end

    # @return [String, nil] The documentation for the method, or `nil` if it's
    #   unavailable.
    def doc
      @doc ||= case source_type
        when :c
          info = pry_doc_info
          info.docstring if info
        when :ruby
          get_comment_content(comment)
        end
    end

    # @return [Symbol] The source type of the method. The options are
    #   `:ruby` for Ruby methods or `:c` for methods written in C.
    def source_type
      source_location.nil? ? :c : :ruby
    end

    # @return [String, nil] The name of the file the method is defined in, or
    #   `nil` if the filename is unavailable.
    def source_file
      if source_location.nil?
        if !rbx? and source_type == :c
          info = pry_doc_info
          info.file if info
        end
      else
        source_location.first
      end
    end

    # @return [Fixnum, nil] The line of code in `source_file` which begins
    #   the method's definition, or `nil` if that information is unavailable.
    def source_line
      source_location.nil? ? nil : source_location.last
    end

    # @return [Range, nil] The range of lines in `source_file` which contain
    #    the method's definition, or `nil` if that information is unavailable.
    def source_range
      source_location.nil? ? nil : (source_line)..(source_line + source.lines.count - 1)
    end

    # @return [Symbol] The visibility of the method. May be `:public`,
    #   `:protected`, or `:private`.
    def visibility
     @visibility ||= if owner.public_instance_methods.any? { |m| m.to_s == name }
                       :public
                     elsif owner.protected_instance_methods.any? { |m| m.to_s == name }
                       :protected
                     elsif owner.private_instance_methods.any? { |m| m.to_s == name }
                       :private
                     else
                       :none
                     end
    end

    # @return [String] A representation of the method's signature, including its
    #   name and parameters. Optional and "rest" parameters are marked with `*`
    #   and block parameters with `&`. If the parameter names are unavailable,
    #   they're given numbered names instead.
    #   Paraphrased from `awesome_print` gem.
    def signature
      if respond_to?(:parameters)
        args = parameters.inject([]) do |arr, (typ, nam)|
          nam ||= (typ == :block ? 'block' : "arg#{arr.size + 1}")
          arr << case typ
                 when :req   then nam.to_s
                 when :opt   then "#{nam}=?"
                 when :rest  then "*#{nam}"
                 when :block then "&#{nam}"
                 else '?'
                 end
        end
      else
        args = (1..arity.abs).map { |i| "arg#{i}" }
        args[-1] = "*#{args[-1]}" if arity < 0
      end

      "#{name}(#{args.join(', ')})"
    end

    # @return [Pry::Method, nil] The wrapped method that is called when you
    #   use "super" in the body of this method.
    def super(times=1)
      if UnboundMethod === @method
        sup = super_using_ancestors(Pry::Method.instance_resolution_order(owner), times)
      else
        sup = super_using_ancestors(Pry::Method.resolution_order(receiver), times)
        sup &&= sup.bind(receiver)
      end
      Pry::Method.new(sup) if sup
    end

    # @return [String, nil] The original name the method was defined under,
    #   before any aliasing, or `nil` if it can't be determined.
    def original_name
      return nil if source_type != :ruby
      method_name_from_first_line(source.lines.first)
    end

    # @return [Boolean] Was the method defined outside a source file?
    def dynamically_defined?
      !!(source_file and source_file =~ /(\(.*\))|<.*>/)
    end

    # @return [Boolean] Whether the method is unbound.
    def unbound_method?
      is_a?(::UnboundMethod)
    end

    # @return [Boolean] Whether the method is bound.
    def bound_method?
      is_a?(::Method)
    end

    # @return [Boolean] Whether the method is a singleton method.
    def singleton_method?
      wrapped_owner.singleton_class?
    end

    # @return [Boolean] Was the method defined within the Pry REPL?
    def pry_method?
      source_file == Pry.eval_path
    end

    # @return [Array<String>] All known aliases for the method.
    def aliases
      owner = @method.owner
      # Avoid using `to_sym` on {Method#name}, which returns a `String`, because
      # it won't be garbage collected.
      name = @method.name

      all_methods_to_compare = owner.instance_methods | owner.private_instance_methods
      alias_list = all_methods_to_compare.combination(2).select do |pair|
        pair.include?(name) &&
          owner.instance_method(pair.first) == owner.instance_method(pair.last)
      end.flatten
      alias_list.delete(name)

      alias_list.map(&:to_s)
    end

    # @return [Boolean] Is the method definitely an alias?
    def alias?
      name != original_name
    end

    # @return [Boolean]
    def ==(obj)
      if obj.is_a? Pry::Method
        obj == @method
      else
        @method == obj
      end
    end

    # @param [Class] klass
    # @return [Boolean]
    def is_a?(klass)
      klass == Pry::Method or @method.is_a?(klass)
    end
    alias kind_of? is_a?

    # @param [String, Symbol] method_name
    # @return [Boolean]
    def respond_to?(method_name, include_all=false)
      super or @method.respond_to?(method_name, include_all)
    end

    # Delegate any unknown calls to the wrapped method.
    def method_missing(method_name, *args, &block)
      @method.send(method_name, *args, &block)
    end

    def comment
      Pry::Code.from_file(source_file).comment_describing(source_line)
    end

    private

    # @return [YARD::CodeObjects::MethodObject]
    # @raise [CommandError] when the method can't be found or `pry-doc` isn't installed.
    def pry_doc_info
      if Pry.config.has_pry_doc
        Pry::MethodInfo.info_for(@method) or raise CommandError, "Cannot locate this method: #{name}. (source_location returns nil)"
      else
        fail_msg = "Cannot locate this method: #{name}."
        if mri?
          fail_msg += " Invoke the 'gem-install pry-doc' Pry command to get access to Ruby Core documentation.\n"
        end
        raise CommandError, fail_msg
      end
    end

    # @param [Class, Module] ancestors The ancestors to investigate
    # @return [Method] The unwrapped super-method
    def super_using_ancestors(ancestors, times=1)
      next_owner = self.owner
      times.times do
        i = ancestors.index(next_owner) + 1
        while ancestors[i] && !(ancestors[i].method_defined?(name) || ancestors[i].private_method_defined?(name))
          i += 1
        end
        next_owner = ancestors[i] or return nil
      end

      safe_send(next_owner, :instance_method, name) rescue nil
    end

    # @param [String] first_ln The first line of a method definition.
    # @return [String, nil]
    def method_name_from_first_line(first_ln)
      return nil if first_ln.strip !~ /^def /

      tokens = CodeRay.scan(first_ln, :ruby)
      tokens = tokens.tokens.each_slice(2) if tokens.respond_to?(:tokens)
      tokens.each_cons(2) do |t1, t2|
        if t2.last == :method || t2.last == :ident && t1 == [".", :operator]
          return t2.first
        end
      end

      nil
    end

    def c_source
      info = pry_doc_info
      if info and info.source
        strip_comments_from_c_code(info.source)
      end
    end

    def ruby_source
      # clone of MethodSource.source_helper that knows to use our
      # hacked version of source_location for rbx core methods, and
      # our input buffer for methods defined in (pry)
      file, line = *source_location
      raise SourceNotFoundError, "Could not locate source for #{name_with_owner}!" unless file

      begin
        code = Pry::Code.from_file(file).expression_at(line)
      rescue SyntaxError => e
        raise MethodSource::SourceNotFoundError.new(e.message)
      end
      strip_leading_whitespace(code)
    end
  end
end
