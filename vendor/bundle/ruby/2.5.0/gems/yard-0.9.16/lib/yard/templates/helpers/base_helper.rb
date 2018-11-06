# frozen_string_literal: true
module YARD::Templates::Helpers
  # The base helper module included in all templates.
  module BaseHelper
    attr_accessor :object, :serializer

    # @return [CodeObjects::Base] the object representing the current generated
    #   page. Might not be the current {#object} when inside sub-templates.
    attr_reader :owner
    undef owner
    def owner; (defined?(@owner) && @owner) || object.namespace end

    # @group Managing Global Template State

    # An object that keeps track of global state throughout the entire template
    # rendering process (including any sub-templates).
    #
    # @return [OpenStruct] a struct object that stores state
    # @since 0.6.0
    def globals; options.globals end

    # @group Running the Verifier

    # Runs a list of objects against the {Verifier} object passed into the
    # template and returns the subset of verified objects.
    #
    # @param [Array<CodeObjects::Base>] list a list of code objects
    # @return [Array<CodeObjects::Base>] a list of code objects that match
    #   the verifier. If no verifier is supplied, all objects are returned.
    def run_verifier(list)
      options.verifier ? options.verifier.run(list) : list
    end

    # @group Escaping Text

    # Escapes text. This is used a lot by the HtmlHelper and there should
    # be some helper to "clean up" text for whatever, this is it.
    def h(text)
      text
    end

    # @group Linking Objects and URLs

    # Links objects or URLs. This method will delegate to the correct +link_+
    # method depending on the arguments passed in.
    #
    # @example Linking a URL
    #   linkify('http://example.com')
    # @example Including docstring contents of an object
    #   linkify('include:YARD::Docstring')
    # @example Linking to an extra file
    #   linkify('file:README')
    # @example Linking an object by path
    #   linkify('YARD::Docstring')
    def linkify(*args)
      if args.first.is_a?(String)
        case args.first
        when %r{://}, /^mailto:/
          link_url(args[0], args[1], {:target => '_parent'}.merge(args[2] || {}))
        when /^include:file:(\S+)/
          file = $1
          relpath = File.relative_path(Dir.pwd, File.expand_path(file))
          if relpath =~ /^\.\./
            log.warn "Cannot include file from path `#{file}'"
            ""
          elsif File.file?(file)
            link_include_file(file)
          else
            log.warn "Cannot find file at `#{file}' for inclusion"
            ""
          end
        when /^include:(\S+)/
          path = $1
          obj = YARD::Registry.resolve(object.namespace, path)
          if obj
            link_include_object(obj)
          else
            log.warn "Cannot find object at `#{path}' for inclusion"
            ""
          end
        when /^render:(\S+)/
          path = $1
          obj = YARD::Registry.resolve(object, path)
          if obj
            opts = options.dup
            opts.delete(:serializer)
            obj.format(opts)
          else
            ''
          end
        when /^file:(\S+?)(?:#(\S+))?$/
          link_file($1, args[1] ? args[1] : nil, $2)
        else
          link_object(*args)
        end
      else
        link_object(*args)
      end
    end

    # Includes an object's docstring into output.
    # @since 0.6.0
    # @param [CodeObjects::Base] obj the object to include
    # @return [String] the object's docstring (no tags)
    def link_include_object(obj)
      obj.docstring
    end

    # Include a file as a docstring in output
    # @since 0.7.0
    # @param [String] file the filename to include
    # @return [String] the file's contents
    def link_include_file(file)
      File.read(file)
    end

    # Links to an object with an optional title
    #
    # @param [CodeObjects::Base] obj the object to link to
    # @param [String] title the title to use for the link
    # @return [String] the linked object
    def link_object(obj, title = nil)
      return title if title

      case obj
      when YARD::CodeObjects::Base, YARD::CodeObjects::Proxy
        obj.title
      when String, Symbol
        P(obj).title
      else
        obj
      end
    end

    # Links to a URL
    #
    # @param [String] url the URL to link to
    # @param [String] title the optional title to display the link as
    # @param [Hash] params optional parameters for the link
    # @return [String] the linked URL
    def link_url(url, title = nil, params = nil) # rubocop:disable Lint/UnusedMethodArgument
      url
    end

    # Links to an extra file
    #
    # @param [String] filename the filename to link to
    # @param [String] title the title of the link
    # @param [String] anchor optional anchor
    # @return [String] the link to the file
    # @since 0.5.5
    def link_file(filename, title = nil, anchor = nil) # rubocop:disable Lint/UnusedMethodArgument
      return filename.filename if CodeObjects::ExtraFileObject === filename
      filename
    end

    # @group Formatting Object Attributes

    # Formats a list of return types for output and links each type.
    #
    # @example Formatting types
    #   format_types(['String', 'Array']) #=> "(String, Array)"
    # @example Formatting types without surrounding brackets
    #   format_types(['String', 'Array'], false) #=> "String, Array"
    # @param [Array<String>] list a list of types
    # @param [Boolean] brackets whether to surround the types in brackets
    # @return [String] the formatted list of Ruby types
    def format_types(list, brackets = true)
      list.nil? || list.empty? ? "" : (brackets ? "(#{list.join(", ")})" : list.join(", "))
    end

    # @example Formatted type of an exception class
    #   o = ClassObject.new(:root, :MyError)
    #   o.superclass = P('RuntimeError')
    #   format_object_type(o) # => "Exception"
    # @example Formatted type of a method
    #   o = MethodObject.new(:root, :to_s)
    #   format_object_type(o) # => "Method"
    # @param [CodeObjects::Base] object the object to retrieve the type for
    # @return [String] the human-readable formatted {CodeObjects::Base#type #type}
    #   for the object
    def format_object_type(object)
      case object
      when YARD::CodeObjects::ClassObject
        object.is_exception? ? "Exception" : "Class"
      else
        object.type.to_s.capitalize
      end
    end

    # @example
    #   s = format_object_title ModuleObject.new(:root, :MyModuleName)
    #   s # => "Module: MyModuleName"
    # @param [CodeObjects::Base] object the object to retrieve a title for
    # @return [String] the page title name for a given object
    def format_object_title(object)
      case object
      when YARD::CodeObjects::RootObject
        "Top Level Namespace"
      else
        format_object_type(object) + ": " + object.title
      end
    end

    # Indents and formats source code
    #
    # @param [String] value the input source code
    # @return [String] formatted source code
    def format_source(value)
      sp = value.split("\n").last[/^(\s+)/, 1]
      num = sp ? sp.size : 0
      value.gsub(/^\s{#{num}}/, '')
    end
  end
end
