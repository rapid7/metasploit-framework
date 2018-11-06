# frozen_string_literal: true
module YARD
  module CodeObjects
    # A list of code objects. This array acts like a set (no unique items)
    # but also disallows any {Proxy} objects from being added.
    class CodeObjectList < Array
      # Creates a new object list associated with a namespace
      #
      # @param [NamespaceObject] owner the namespace the list should be associated with
      # @return [CodeObjectList]
      def initialize(owner = Registry.root)
        @owner = owner
      end

      # Adds a new value to the list
      #
      # @param [Base] value a code object to add
      # @return [CodeObjectList] self
      def push(value)
        value = Proxy.new(@owner, value) if value.is_a?(String) || value.is_a?(Symbol)
        if value.is_a?(CodeObjects::Base) || value.is_a?(Proxy)
          super(value) unless include?(value)
        else
          raise ArgumentError, "#{value.class} is not a valid CodeObject"
        end
        self
      end
      alias << push
    end

    extend NamespaceMapper

    # Namespace separator
    NSEP = '::'

    # Regex-quoted namespace separator
    NSEPQ = NSEP

    # Instance method separator
    ISEP = '#'

    # Regex-quoted instance method separator
    ISEPQ = ISEP

    # Class method separator
    CSEP = '.'

    # Regex-quoted class method separator
    CSEPQ = Regexp.quote CSEP

    # Regular expression to match constant name
    CONSTANTMATCH = /[A-Z]\w*/

    # Regular expression to match the beginning of a constant
    CONSTANTSTART = /^[A-Z]/

    # Regular expression to match namespaces (const A or complex path A::B)
    NAMESPACEMATCH = /(?:(?:#{NSEPQ}\s*)?#{CONSTANTMATCH})+/

    # Regular expression to match a method name
    METHODNAMEMATCH = %r{[a-zA-Z_]\w*[!?=]?|[-+~]\@|<<|>>|=~|===?|![=~]?|<=>|[<>]=?|\*\*|[-/+%^&*~`|]|\[\]=?}

    # Regular expression to match a fully qualified method def (self.foo, Class.foo).
    METHODMATCH = /(?:(?:#{NAMESPACEMATCH}|[a-z]\w*)\s*(?:#{CSEPQ}|#{NSEPQ})\s*)?#{METHODNAMEMATCH}/

    # All builtin Ruby exception classes for inheritance tree.
    BUILTIN_EXCEPTIONS = ["ArgumentError", "ClosedQueueError", "EncodingError",
      "EOFError", "Exception", "FiberError", "FloatDomainError", "IndexError",
      "Interrupt", "IOError", "KeyError", "LoadError", "LocalJumpError",
      "NameError", "NoMemoryError", "NoMethodError", "NotImplementedError",
      "RangeError", "RegexpError", "RuntimeError", "ScriptError", "SecurityError",
      "SignalException", "StandardError", "StopIteration", "SyntaxError",
      "SystemCallError", "SystemExit", "SystemStackError", "ThreadError",
      "TypeError", "UncaughtThrowError", "ZeroDivisionError"]

    # All builtin Ruby classes for inheritance tree.
    # @note MatchingData is a 1.8.x legacy class
    BUILTIN_CLASSES = ["Array", "Bignum", "Binding", "Class", "Complex",
      "ConditionVariable", "Data", "Dir", "Encoding", "Enumerator", "FalseClass",
      "Fiber", "File", "Fixnum", "Float", "Hash", "IO", "Integer", "MatchData",
      "Method", "Module", "NilClass", "Numeric", "Object", "Proc", "Queue",
      "Random", "Range", "Rational", "Regexp", "RubyVM", "SizedQueue", "String",
      "Struct", "Symbol", "Thread", "ThreadGroup", "Time", "TracePoint",
      "TrueClass", "UnboundMethod"] + BUILTIN_EXCEPTIONS

    # All builtin Ruby modules for mixin handling.
    BUILTIN_MODULES = ["Comparable", "Enumerable", "Errno", "FileTest", "GC",
      "Kernel", "Marshal", "Math", "ObjectSpace", "Precision", "Process", "Signal"]

    # All builtin Ruby classes and modules.
    BUILTIN_ALL = BUILTIN_CLASSES + BUILTIN_MODULES

    # Hash of {BUILTIN_EXCEPTIONS} as keys and true as value (for O(1) lookups)
    BUILTIN_EXCEPTIONS_HASH = BUILTIN_EXCEPTIONS.inject({}) {|h, n| h.update(n => true) }

    # +Base+ is the superclass of all code objects recognized by YARD. A code
    # object is any entity in the Ruby language (class, method, module). A
    # DSL might subclass +Base+ to create a new custom object representing
    # a new entity type.
    #
    # == Registry Integration
    # Any created object associated with a namespace is immediately registered
    # with the registry. This allows the Registry to act as an identity map
    # to ensure that no object is represented by more than one Ruby object
    # in memory. A unique {#path} is essential for this identity map to work
    # correctly.
    #
    # == Custom Attributes
    # Code objects allow arbitrary custom attributes to be set using the
    # {#[]=} assignment method.
    #
    # == Namespaces
    # There is a special type of object called a "namespace". These are subclasses
    # of the {NamespaceObject} and represent Ruby entities that can have
    # objects defined within them. Classically these are modules and classes,
    # though a DSL might create a custom {NamespaceObject} to describe a
    # specific set of objects.
    #
    # == Separators
    # Custom classes with different separator tokens should define their own
    # separators using the {NamespaceMapper.register_separator} method. The
    # standard Ruby separators have already been defined ('::', '#', '.', etc).
    #
    # @abstract This class should not be used directly. Instead, create a
    #   subclass that implements {#path}, {#sep} or {#type}. You might also
    #   need to register custom separators if {#sep} uses alternate separator
    #   tokens.
    # @see Registry
    # @see #path
    # @see #[]=
    # @see NamespaceObject
    # @see NamespaceMapper.register_separator
    class Base
      # The files the object was defined in. To add a file, use {#add_file}.
      # @return [Array<Array(String, Integer)>] a list of files
      # @see #add_file
      attr_reader :files

      # The namespace the object is defined in. If the object is in the
      # top level namespace, this is {Registry.root}
      # @return [NamespaceObject] the namespace object
      attr_reader :namespace

      # The source code associated with the object
      # @return [String, nil] source, if present, or nil
      attr_reader :source

      # Language of the source code associated with the object. Defaults to
      # +:ruby+.
      #
      # @return [Symbol] the language type
      attr_accessor :source_type

      # The one line signature representing an object. For a method, this will
      # be of the form "def meth(arguments...)". This is usually the first
      # source line.
      #
      # @return [String] a line of source
      attr_accessor :signature

      # The non-localized documentation string associated with the object
      # @return [Docstring] the documentation string
      # @since 0.8.4
      attr_reader :base_docstring
      undef base_docstring
      def base_docstring; @docstring end

      # Marks whether or not the method is conditionally defined at runtime
      # @return [Boolean] true if the method is conditionally defined at runtime
      attr_accessor :dynamic

      # @return [String] the group this object is associated with
      # @since 0.6.0
      attr_accessor :group

      # Is the object defined conditionally at runtime?
      # @see #dynamic
      def dynamic?; @dynamic end

      # @return [Symbol] the visibility of an object (:public, :private, :protected)
      attr_accessor :visibility
      undef visibility=
      def visibility=(v) @visibility = v.to_sym end

      class << self
        # Allocates a new code object
        # @return [Base]
        # @see #initialize
        def new(namespace, name, *args, &block)
          raise ArgumentError, "invalid empty object name" if name.to_s.empty?
          if namespace.is_a?(ConstantObject)
            namespace = Proxy.new(namespace.namespace, namespace.value)
          end

          if name.to_s[0, 2] == NSEP
            name = name.to_s[2..-1]
            namespace = Registry.root
          end

          if name =~ /(?:#{NSEPQ})([^:]+)$/
            return new(Proxy.new(namespace, $`), $1, *args, &block)
          end

          obj = super(namespace, name, *args)
          existing_obj = Registry.at(obj.path)
          obj = existing_obj if existing_obj && existing_obj.class == self
          yield(obj) if block_given?
          obj
        end

        # Compares the class with subclasses
        #
        # @param [Object] other the other object to compare classes with
        # @return [Boolean] true if other is a subclass of self
        def ===(other)
          other.is_a?(self)
        end
      end

      # Creates a new code object
      #
      # @example Create a method in the root namespace
      #   CodeObjects::Base.new(:root, '#method') # => #<yardoc method #method>
      # @example Create class Z inside namespace X::Y
      #   CodeObjects::Base.new(P("X::Y"), :Z) # or
      #   CodeObjects::Base.new(Registry.root, "X::Y")
      # @param [NamespaceObject] namespace the namespace the object belongs in,
      #   {Registry.root} or :root should be provided if it is associated with
      #   the top level namespace.
      # @param [Symbol, String] name the name (or complex path) of the object.
      # @yield [self] a block to perform any extra initialization on the object
      # @yieldparam [Base] self the newly initialized code object
      # @return [Base] the newly created object
      def initialize(namespace, name, *)
        if namespace && namespace != :root &&
           !namespace.is_a?(NamespaceObject) && !namespace.is_a?(Proxy)
          raise ArgumentError, "Invalid namespace object: #{namespace}"
        end

        @files = []
        @current_file_has_comments = false
        @name = name.to_sym
        @source_type = :ruby
        @visibility = :public
        @tags = []
        @docstrings = {}
        @docstring = Docstring.new!('', [], self)
        @namespace = nil
        self.namespace = namespace
        yield(self) if block_given?
      end

      # Copies all data in this object to another code object, except for
      # uniquely identifying information (path, namespace, name, scope).
      #
      # @param [Base] other the object to copy data to
      # @return [Base] the other object
      # @since 0.8.0
      def copy_to(other)
        copyable_attributes.each do |ivar|
          ivar = "@#{ivar}"
          other.instance_variable_set(ivar, instance_variable_get(ivar))
        end
        other.docstring = @docstring.to_raw
        other
      end

      # The name of the object
      # @param [Boolean] prefix whether to show a prefix. Implement
      #   this in a subclass to define how the prefix is showed.
      # @return [Symbol] if prefix is false, the symbolized name
      # @return [String] if prefix is true, prefix + the name as a String.
      #   This must be implemented by the subclass.
      def name(prefix = false)
        prefix ? @name.to_s : (defined?(@name) && @name)
      end

      # Associates a file with a code object, optionally adding the line where it was defined.
      # By convention, '<stdin>' should be used to associate code that comes form standard input.
      #
      # @param [String] file the filename ('<stdin>' for standard input)
      # @param [Fixnum, nil] line the line number where the object lies in the file
      # @param [Boolean] has_comments whether or not the definition has comments associated. This
      #   will allow {#file} to return the definition where the comments were made instead
      #   of any empty definitions that might have been parsed before (module namespaces for instance).
      def add_file(file, line = nil, has_comments = false)
        raise(ArgumentError, "file cannot be nil or empty") if file.nil? || file == ''
        obj = [file.to_s, line]
        return if files.include?(obj)
        if has_comments && !@current_file_has_comments
          @current_file_has_comments = true
          @files.unshift(obj)
        else
          @files << obj # back of the line
        end
      end

      # Returns the filename the object was first parsed at, taking
      # definitions with docstrings first.
      #
      # @return [String] a filename
      def file
        @files.first ? @files.first[0] : nil
      end

      # Returns the line the object was first parsed at (or nil)
      #
      # @return [Fixnum] the line where the object was first defined.
      # @return [nil] if there is no line associated with the object
      def line
        @files.first ? @files.first[1] : nil
      end

      # Tests if another object is equal to this, including a proxy
      # @param [Base, Proxy] other if other is a {Proxy}, tests if
      #   the paths are equal
      # @return [Boolean] whether or not the objects are considered the same
      def equal?(other)
        if other.is_a?(Base) || other.is_a?(Proxy)
          path == other.path
        else
          super
        end
      end
      alias == equal?
      alias eql? equal?

      # @return [Integer] the object's hash value (for equality checking)
      def hash; path.hash end

      # @return [nil] this object does not turn into an array
      def to_ary; nil end

      # Accesses a custom attribute on the object
      # @param [#to_s] key the name of the custom attribute
      # @return [Object, nil] the custom attribute or nil if not found.
      # @see #[]=
      def [](key)
        if respond_to?(key)
          send(key)
        elsif instance_variable_defined?("@#{key}")
          instance_variable_get("@#{key}")
        end
      end

      # Sets a custom attribute on the object
      # @param [#to_s] key the name of the custom attribute
      # @param [Object] value the value to associate
      # @return [void]
      # @see #[]
      def []=(key, value)
        if respond_to?("#{key}=")
          send("#{key}=", value)
        else
          instance_variable_set("@#{key}", value)
        end
      end

      # @overload dynamic_attr_name
      #   @return the value of attribute named by the method attribute name
      #   @raise [NoMethodError] if no method or custom attribute exists by
      #     the attribute name
      #   @see #[]
      # @overload dynamic_attr_name=(value)
      #   @param value a value to set
      #   @return +value+
      #   @see #[]=
      def method_missing(meth, *args, &block)
        if meth.to_s =~ /=$/
          self[meth.to_s[0..-2]] = args.first
        elsif instance_variable_get("@#{meth}")
          self[meth]
        else
          super
        end
      end

      # Attaches source code to a code object with an optional file location
      #
      # @param [#source, String] statement
      #   the +Parser::Statement+ holding the source code or the raw source
      #   as a +String+ for the definition of the code object only (not the block)
      def source=(statement)
        if statement.respond_to?(:source)
          self.signature = statement.first_line
          @source = format_source(statement.source.strip)
        else
          @source = format_source(statement.to_s)
        end
      end

      # The documentation string associated with the object
      #
      # @param [String, I18n::Locale] locale (I18n::Locale.default)
      #   the locale of the documentation string.
      # @return [Docstring] the documentation string
      def docstring(locale = I18n::Locale.default)
        if locale.nil?
          @docstring.resolve_reference
          return @docstring
        end

        if locale.is_a?(String)
          locale_name = locale
          locale = nil
        else
          locale_name = locale.name
        end
        @docstrings[locale_name] ||=
          translate_docstring(locale || Registry.locale(locale_name))
      end

      # Attaches a docstring to a code object by parsing the comments attached to the statement
      # and filling the {#tags} and {#docstring} methods with the parsed information.
      #
      # @param [String, Array<String>, Docstring] comments
      #   the comments attached to the code object to be parsed
      #   into a docstring and meta tags.
      def docstring=(comments)
        @docstrings.clear
        @docstring = Docstring === comments ?
          comments : Docstring.new(comments, self)
      end

      # Default type is the lowercase class name without the "Object" suffix.
      # Override this method to provide a custom object type
      #
      # @return [Symbol] the type of code object this represents
      def type
        self.class.name.split('::').last.gsub(/Object$/, '').downcase.to_sym
      end

      # Represents the unique path of the object. The default implementation
      # joins the path of {#namespace} with {#name} via the value of {#sep}.
      # Custom code objects should ensure that the path is unique to the code
      # object by either overriding {#sep} or this method.
      #
      # @example The path of an instance method
      #   MethodObject.new(P("A::B"), :c).path # => "A::B#c"
      # @return [String] the unique path of the object
      # @see #sep
      def path
        @path ||= if parent && !parent.root?
                    [parent.path, name.to_s].join(sep)
                  else
                    name.to_s
                  end
      end
      alias to_s path

      # @note
      #   Override this method if your object has a special title that does
      #   not match the {#path} attribute value. This title will be used
      #   when linking or displaying the object.
      # @return [String] the display title for an object
      # @see 0.8.4
      def title
        path
      end

      # @param [Base, String] other another code object (or object path)
      # @return [String] the shortest relative path from this object to +other+
      # @since 0.5.3
      def relative_path(other)
        other = Registry.at(other) if String === other && Registry.at(other)
        same_parent = false
        if other.respond_to?(:path)
          same_parent = other.parent == parent
          other = other.path
        end
        return other unless namespace
        common = [path, other].join(" ").match(/^(\S*)\S*(?: \1\S*)*$/)[1]
        common = path unless common =~ /(\.|::|#)$/
        common = common.sub(/(\.|::|#)[^:#\.]*?$/, '') if same_parent
        suffix = %w(. :).include?(common[-1, 1]) || other[common.size, 1] == '#' ?
          '' : '(::|\.)'
        result = other.sub(/^#{Regexp.quote common}#{suffix}/, '')
        result.empty? ? other : result
      end

      # Renders the object using the {Templates::Engine templating system}.
      #
      # @example Formats a class in plaintext
      #   puts P('MyClass').format
      # @example Formats a method in html with rdoc markup
      #   puts P('MyClass#meth').format(:format => :html, :markup => :rdoc)
      # @param [Hash] options a set of options to pass to the template
      # @option options [Symbol] :format (:text) :html, :text or another output format
      # @option options [Symbol] :template (:default) a specific template to use
      # @option options [Symbol] :markup (nil) the markup type (:rdoc, :markdown, :textile)
      # @option options [Serializers::Base] :serializer (nil) see Serializers
      # @return [String] the rendered template
      # @see Templates::Engine#render
      def format(options = {})
        options = options.merge(:object => self)
        options = options.merge(:type => type) unless options[:type]
        Templates::Engine.render(options)
      end

      # Inspects the object, returning the type and path
      # @return [String] a string describing the object
      def inspect
        "#<yardoc #{type} #{path}>"
      end

      # Sets the namespace the object is defined in.
      #
      # @param [NamespaceObject, :root, nil] obj the new namespace (:root
      #   for {Registry.root}). If obj is nil, the object is unregistered
      #   from the Registry.
      def namespace=(obj)
        if @namespace
          @namespace.children.delete(self)
          Registry.delete(self)
        end

        @namespace = (obj == :root ? Registry.root : obj)

        if @namespace
          reg_obj = Registry.at(path)
          return if reg_obj && reg_obj.class == self.class
          @namespace.children << self unless @namespace.is_a?(Proxy)
          Registry.register(self)
        end
      end

      alias parent namespace
      alias parent= namespace=

      # Gets a tag from the {#docstring}
      # @see Docstring#tag
      def tag(name); docstring.tag(name) end

      # Gets a list of tags from the {#docstring}
      # @see Docstring#tags
      def tags(name = nil); docstring.tags(name) end

      # Tests if the {#docstring} has a tag
      # @see Docstring#has_tag?
      def has_tag?(name); docstring.has_tag?(name) end

      # Add tags to the {#docstring}
      # @see Docstring#add_tag
      # @since 0.8.4
      def add_tag(*tags)
        @docstrings.clear
        @docstring.add_tag(*tags)
      end

      # @return whether or not this object is a RootObject
      def root?; false end

      # Override this method with a custom component separator. For instance,
      # {MethodObject} implements sep as '#' or '.' (depending on if the
      # method is instance or class respectively). {#path} depends on this
      # value to generate the full path in the form: namespace.path + sep + name
      #
      # @return [String] the component that separates the namespace path
      #   and the name (default is {NSEP})
      def sep; NSEP end

      protected

      # Override this method if your code object subclass does not allow
      # copying of certain attributes.
      #
      # @return [Array<String>] the list of instance variable names (without
      #   "@" prefix) that should be copied when {#copy_to} is called
      # @see #copy_to
      # @since 0.8.0
      def copyable_attributes
        vars = instance_variables.map {|ivar| ivar.to_s[1..-1] }
        vars -= %w(docstring docstrings namespace name path)
        vars
      end

      private

      # Formats source code by removing leading indentation
      #
      # @param [String] source the source code to format
      # @return [String] formatted source
      def format_source(source)
        source = source.chomp
        last = source.split(/\r?\n/).last
        indent = last ? last[/^([ \t]*)/, 1].length : 0
        source.gsub(/^[ \t]{#{indent}}/, '')
      end

      def translate_docstring(locale)
        @docstring.resolve_reference
        return @docstring if locale.nil?

        text = I18n::Text.new(@docstring)
        localized_text = text.translate(locale)
        docstring = Docstring.new(localized_text, self)
        @docstring.tags.each do |tag|
          if tag.is_a?(Tags::Tag)
            localized_tag = tag.clone
            localized_tag.text = I18n::Text.new(tag.text).translate(locale)
            docstring.add_tag(localized_tag)
          else
            docstring.add_tag(tag)
          end
        end
        docstring
      end
    end
  end
end
