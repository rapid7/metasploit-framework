# frozen_string_literal: true
module YARD
  module CodeObjects
    # A special type of +NoMethodError+ when raised from a {Proxy}
    class ProxyMethodError < NoMethodError; end

    # @private
    PROXY_MATCH = /(?:#{NSEPQ}|#{ISEPQ}|#{CSEPQ})([^#{Regexp.quote(
      (NSEP + ISEP + CSEP).split('').uniq.join
    )}]+)$/

    # The Proxy class is a way to lazily resolve code objects in
    # cases where the object may not yet exist. A proxy simply stores
    # an unresolved path until a method is called on the object, at which
    # point it does a lookup using {Registry.resolve}. If the object is
    # not found, a warning is raised and {ProxyMethodError} might be raised.
    #
    # @example Creates a Proxy to the String class from a module
    #   # When the String class is parsed this method will
    #   # begin to act like the String ClassObject.
    #   Proxy.new(mymoduleobj, "String")
    # @see Registry.resolve
    # @see ProxyMethodError
    class Proxy
      def self.===(other) other.is_a?(self) end

      attr_reader :namespace
      alias parent namespace

      # Creates a new Proxy
      #
      # @raise [ArgumentError] if namespace is not a NamespaceObject
      # @return [Proxy] self
      def initialize(namespace, name, type = nil)
        namespace = Registry.root if !namespace || namespace == :root

        if name =~ /^#{NSEPQ}/
          namespace = Registry.root
          name = name[2..-1]
        end

        if name =~ PROXY_MATCH
          @orignamespace = namespace
          @origname = name
          @imethod = true if name.include? ISEP
          namespace = Proxy.new(namespace, $`) unless $`.empty?
          name = $1
        else
          @orignamespace = nil
          @origname = nil
          @imethod = nil
        end

        @name = name.to_sym
        @namespace = namespace
        @obj = nil
        @imethod ||= nil
        self.type = type

        if @namespace.is_a?(ConstantObject)
          @origname = nil # forget these for a constant
          @orignamespace = nil
          @namespace = Proxy.new(@namespace.namespace, @namespace.value)
        end

        unless @namespace.is_a?(NamespaceObject) || @namespace.is_a?(Proxy)
          raise ArgumentError, "Invalid namespace object: #{namespace}"
        end

        # If the name begins with "::" (like "::String")
        # this is definitely a root level object, so
        # remove the namespace and attach it to the root
        if @name =~ /^#{NSEPQ}/
          @name.gsub!(/^#{NSEPQ}/, '')
          @namespace = Registry.root
        end
      end

      # (see Base#name)
      def name(prefix = false)
        prefix ? "#{@imethod && ISEP}#{@name}" : @name
      end

      # Returns a text representation of the Proxy
      # @return [String] the object's #inspect method or P(OBJECTPATH)
      def inspect
        to_obj ? to_obj.inspect : "P(#{path})"
      end

      # If the proxy resolves to an object, returns its path, otherwise
      # guesses at the correct path using the original namespace and name.
      #
      # @return [String] the assumed path of the proxy (or the real path
      #   of the resolved object)
      def path
        to_obj ? to_obj.path : proxy_path
      end
      alias to_s path
      alias to_str path
      alias title path

      # @return [Boolean]
      def is_a?(klass)
        to_obj ? to_obj.is_a?(klass) : self.class <= klass
      end

      # @return [Boolean]
      def ===(other)
        to_obj ? to_obj === other : self.class <= other.class
      end

      # @return [Boolean]
      def <=>(other)
        if other.respond_to? :path
          path <=> other.path
        else
          false
        end
      end

      # @return [Boolean]
      def equal?(other)
        if other.respond_to? :path
          path == other.path
        else
          false
        end
      end
      alias == equal?

      # @return [Integer] the object's hash value (for equality checking)
      def hash; path.hash end

      # Returns the class name of the object the proxy is mimicking, if
      # resolved. Otherwise returns +Proxy+.
      # @return [Class] the resolved object's class or +Proxy+
      def class
        to_obj ? to_obj.class : Proxy
      end

      # Returns the type of the proxy. If it cannot be resolved at the
      # time of the call, it will either return the inferred proxy type
      # (see {#type=}) or +:proxy+
      # @return [Symbol] the Proxy's type
      # @see #type=
      def type
        to_obj ? to_obj.type : @type || :proxy
      end

      # Allows a parser to infer the type of the proxy by its path.
      # @param [#to_sym] type the proxy's inferred type
      # @return [void]
      def type=(type) @type = type ? type.to_sym : nil end

      # @return [Boolean]
      def instance_of?(klass)
        self.class == klass
      end

      # @return [Boolean]
      def kind_of?(klass)
        self.class <= klass
      end

      # @return [Boolean]
      def respond_to?(meth, include_private = false)
        to_obj ? to_obj.respond_to?(meth, include_private) : super
      end

      # Dispatches the method to the resolved object.
      #
      # @raise [ProxyMethodError] if the proxy cannot find the real object
      def method_missing(meth, *args, &block)
        if to_obj
          to_obj.__send__(meth, *args, &block)
        else
          log.warn "Load Order / Name Resolution Problem on #{path}:\n" \
                   "-\n" \
                   "Something is trying to call #{meth} on object #{path} before it has been recognized.\n" \
                   "This error usually means that you need to modify the order in which you parse files\n" \
                   "so that #{path} is parsed before methods or other objects attempt to access it.\n" \
                   "-\n" \
                   "YARD will recover from this error and continue to parse but you *may* have problems\n" \
                   "with your generated documentation. You should probably fix this.\n" \
                   "-\n"
          begin
            super
          rescue NoMethodError
            raise ProxyMethodError, "Proxy cannot call method ##{meth} on object '#{path}'"
          end
        end
      end

      # This class is never a root object
      def root?; false end

      private

      # @note this method fixes a bug in 1.9.2: http://gist.github.com/437136
      def to_ary; nil end

      # Attempts to find the object that this unresolved object
      # references by checking if any objects by this name are
      # registered all the way up the namespace tree.
      #
      # @return [Base, nil] the registered code object or nil
      def to_obj
        return @obj if @obj
        @obj = Registry.resolve(@namespace, (@imethod ? ISEP : '') + @name.to_s, false, false, @type)
        if @obj
          if @origname && @origname.include?("::") && !@obj.path.include?(@origname)
            # the object's path should include the original proxy namespace,
            # otherwise it's (probably) not the right object.
            @obj = nil
          else
            @namespace = @obj.namespace
            @name = @obj.name
          end
        end
        @obj
      end

      def proxy_path
        if @namespace.root?
          (@imethod ? ISEP : "") + name.to_s
        elsif @origname
          if @origname =~ CONSTANTSTART
            @origname
          else
            [namespace.path, @origname].join
          end
        elsif name.to_s =~ CONSTANTSTART
          name.to_s
        else # class meth?
          [namespace.path, name.to_s].join(CSEP)
        end
      end
    end
  end
end
