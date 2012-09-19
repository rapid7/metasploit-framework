require 'pathname'
require 'shellwords'
require 'tilt'
require 'yaml'

module Sprockets
  # The `DirectiveProcessor` is responsible for parsing and evaluating
  # directive comments in a source file.
  #
  # A directive comment starts with a comment prefix, followed by an "=",
  # then the directive name, then any arguments.
  #
  #     // JavaScript
  #     //= require "foo"
  #
  #     # CoffeeScript
  #     #= require "bar"
  #
  #     /* CSS
  #      *= require "baz"
  #      */
  #
  # The Processor is implemented as a `Tilt::Template` and is loosely
  # coupled to Sprockets. This makes it possible to disable or modify
  # the processor to do whatever you'd like. You could add your own
  # custom directives or invent your own directive syntax.
  #
  # `Environment#processors` includes `DirectiveProcessor` by default.
  #
  # To remove the processor entirely:
  #
  #     env.unregister_processor('text/css', Sprockets::DirectiveProcessor)
  #     env.unregister_processor('application/javascript', Sprockets::DirectiveProcessor)
  #
  # Then inject your own preprocessor:
  #
  #     env.register_processor('text/css', MyProcessor)
  #
  class DirectiveProcessor < Tilt::Template
    # Directives will only be picked up if they are in the header
    # of the source file. C style (/* */), JavaScript (//), and
    # Ruby (#) comments are supported.
    #
    # Directives in comments after the first non-whitespace line
    # of code will not be processed.
    #
    HEADER_PATTERN = /
      \A (
        (?m:\s*) (
          (\/\* (?m:.*?) \*\/) |
          (\#\#\# (?m:.*?) \#\#\#) |
          (\/\/ .* \n?)+ |
          (\# .* \n?)+
        )
      )+
    /x

    # Directives are denoted by a `=` followed by the name, then
    # argument list.
    #
    # A few different styles are allowed:
    #
    #     // =require foo
    #     //= require foo
    #     //= require "foo"
    #
    DIRECTIVE_PATTERN = /
      ^ [\W]* = \s* (\w+.*?) (\*\/)? $
    /x

    attr_reader :pathname
    attr_reader :header, :body

    def prepare
      @pathname = Pathname.new(file)

      @header = data[HEADER_PATTERN, 0] || ""
      @body   = $' || data
      # Ensure body ends in a new line
      @body  += "\n" if @body != "" && @body !~ /\n\Z/m

      @included_pathnames = []
      @compat             = false
    end

    # Implemented for Tilt#render.
    #
    # `context` is a `Context` instance with methods that allow you to
    # access the environment and append to the bundle. See `Context`
    # for the complete API.
    def evaluate(context, locals, &block)
      @context = context

      @result = ""
      @has_written_body = false

      process_directives
      process_source

      @result
    end

    # Returns the header String with any directives stripped.
    def processed_header
      lineno = 0
      @processed_header ||= header.lines.map { |line|
        lineno += 1
        # Replace directive line with a clean break
        directives.assoc(lineno) ? "\n" : line
      }.join.chomp
    end

    # Returns the source String with any directives stripped.
    def processed_source
      @processed_source ||= processed_header + body
    end

    # Returns an Array of directive structures. Each structure
    # is an Array with the line number as the first element, the
    # directive name as the second element, followed by any
    # arguments.
    #
    #     [[1, "require", "foo"], [2, "require", "bar"]]
    #
    def directives
      @directives ||= header.lines.each_with_index.map { |line, index|
        if directive = line[DIRECTIVE_PATTERN, 1]
          name, *args = Shellwords.shellwords(directive)
          if respond_to?("process_#{name}_directive")
            [index + 1, name, *args]
          end
        end
      }.compact
    end

    protected
      attr_reader :included_pathnames
      attr_reader :context

      # Gathers comment directives in the source and processes them.
      # Any directive method matching `process_*_directive` will
      # automatically be available. This makes it easy to extend the
      # processor.
      #
      # To implement a custom directive called `require_glob`, subclass
      # `Sprockets::DirectiveProcessor`, then add a method called
      # `process_require_glob_directive`.
      #
      #     class DirectiveProcessor < Sprockets::DirectiveProcessor
      #       def process_require_glob_directive
      #         Dir["#{pathname.dirname}/#{glob}"].sort.each do |filename|
      #           require(filename)
      #         end
      #       end
      #     end
      #
      # Replace the current processor on the environment with your own:
      #
      #     env.unregister_processor('text/css', Sprockets::DirectiveProcessor)
      #     env.register_processor('text/css', DirectiveProcessor)
      #
      def process_directives
        directives.each do |line_number, name, *args|
          context.__LINE__ = line_number
          send("process_#{name}_directive", *args)
          context.__LINE__ = nil
        end
      end

      def process_source
        unless @has_written_body || processed_header.empty?
          @result << processed_header << "\n"
        end

        included_pathnames.each do |pathname|
          @result << context.evaluate(pathname)
        end

        unless @has_written_body
          @result << body
        end

        if compat? && constants.any?
          @result.gsub!(/<%=(.*?)%>/) { constants[$1.strip] }
        end
      end

      # The `require` directive functions similar to Ruby's own `require`.
      # It provides a way to declare a dependency on a file in your path
      # and ensures its only loaded once before the source file.
      #
      # `require` works with files in the environment path:
      #
      #     //= require "foo.js"
      #
      # Extensions are optional. If your source file is ".js", it
      # assumes you are requiring another ".js".
      #
      #     //= require "foo"
      #
      # Relative paths work too. Use a leading `./` to denote a relative
      # path:
      #
      #     //= require "./bar"
      #
      def process_require_directive(path)
        if @compat
          if path =~ /<([^>]+)>/
            path = $1
          else
            path = "./#{path}" unless relative?(path)
          end
        end

        context.require_asset(path)
      end

      # `require_self` causes the body of the current file to be
      # inserted before any subsequent `require` or `include`
      # directives. Useful in CSS files, where it's common for the
      # index file to contain global styles that need to be defined
      # before other dependencies are loaded.
      #
      #     /*= require "reset"
      #      *= require_self
      #      *= require_tree .
      #      */
      #
      def process_require_self_directive
        if @has_written_body
          raise ArgumentError, "require_self can only be called once per source file"
        end

        context.require_asset(pathname)
        process_source
        included_pathnames.clear
        @has_written_body = true
      end

      # The `include` directive works similar to `require` but
      # inserts the contents of the dependency even if it already
      # has been required.
      #
      #     //= include "header"
      #
      def process_include_directive(path)
        pathname = context.resolve(path)
        context.depend_on_asset(pathname)
        included_pathnames << pathname
      end

      # `require_directory` requires all the files inside a single
      # directory. It's similar to `path/*` since it does not follow
      # nested directories.
      #
      #     //= require_directory "./javascripts"
      #
      def process_require_directory_directive(path = ".")
        if relative?(path)
          root = pathname.dirname.join(path).expand_path

          unless (stats = stat(root)) && stats.directory?
            raise ArgumentError, "require_tree argument must be a directory"
          end

          context.depend_on(root)

          entries(root).each do |pathname|
            pathname = root.join(pathname)
            if pathname.to_s == self.file
              next
            elsif context.asset_requirable?(pathname)
              context.require_asset(pathname)
            end
          end
        else
          # The path must be relative and start with a `./`.
          raise ArgumentError, "require_directory argument must be a relative path"
        end
      end

      # `require_tree` requires all the nested files in a directory.
      # Its glob equivalent is `path/**/*`.
      #
      #     //= require_tree "./public"
      #
      def process_require_tree_directive(path = ".")
        if relative?(path)
          root = pathname.dirname.join(path).expand_path

          unless (stats = stat(root)) && stats.directory?
            raise ArgumentError, "require_tree argument must be a directory"
          end

          context.depend_on(root)

          each_entry(root) do |pathname|
            if pathname.to_s == self.file
              next
            elsif stat(pathname).directory?
              context.depend_on(pathname)
            elsif context.asset_requirable?(pathname)
              context.require_asset(pathname)
            end
          end
        else
          # The path must be relative and start with a `./`.
          raise ArgumentError, "require_tree argument must be a relative path"
        end
      end

      # Allows you to state a dependency on a file without
      # including it.
      #
      # This is used for caching purposes. Any changes made to
      # the dependency file will invalidate the cache of the
      # source file.
      #
      # This is useful if you are using ERB and File.read to pull
      # in contents from another file.
      #
      #     //= depend_on "foo.png"
      #
      def process_depend_on_directive(path)
        context.depend_on(path)
      end

      # Allows you to state a dependency on an asset without including
      # it.
      #
      # This is used for caching purposes. Any changes that would
      # invalid the asset dependency will invalidate the cache our the
      # source file.
      #
      # Unlike `depend_on`, the path must be a requirable asset.
      #
      #     //= depend_on_asset "bar.js"
      #
      def process_depend_on_asset_directive(path)
        context.depend_on_asset(path)
      end

      # Enable Sprockets 1.x compat mode.
      #
      # Makes it possible to use the same JavaScript source
      # file in both Sprockets 1 and 2.
      #
      #     //= compat
      #
      def process_compat_directive
        @compat = true
      end

      # Checks if Sprockets 1.x compat mode enabled
      def compat?
        @compat
      end

      # Sprockets 1.x allowed for constant interpolation if a
      # constants.yml was present. This is only available if
      # compat mode is on.
      def constants
        if compat?
          pathname = Pathname.new(context.root_path).join("constants.yml")
          stat(pathname) ? YAML.load_file(pathname) : {}
        else
          {}
        end
      end

      # `provide` is stubbed out for Sprockets 1.x compat.
      # Mutating the path when an asset is being built is
      # not permitted.
      def process_provide_directive(path)
      end

    private
      def relative?(path)
        path =~ /^\.($|\.?\/)/
      end

      def stat(path)
        context.environment.stat(path)
      end

      def entries(path)
        context.environment.entries(path)
      end

      def each_entry(root, &block)
        context.environment.each_entry(root, &block)
      end
  end
end
