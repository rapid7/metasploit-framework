require 'base64'
require 'rack/utils'
require 'sprockets/errors'
require 'sprockets/utils'
require 'pathname'
require 'set'

module Sprockets
  # `Context` provides helper methods to all `Tilt` processors. They
  # are typically accessed by ERB templates. You can mix in custom
  # helpers by injecting them into `Environment#context_class`. Do not
  # mix them into `Context` directly.
  #
  #     environment.instance_eval do
  #       include MyHelper
  #       def asset_url; end
  #     end
  #
  #     <%= asset_url "foo.png" %>
  #
  # The `Context` also collects dependencies declared by
  # assets. See `DirectiveProcessor` for an example of this.
  class Context
    attr_reader :environment, :pathname
    attr_reader :_required_paths, :_dependency_paths, :_dependency_assets
    attr_writer :__LINE__

    def initialize(environment, logical_path, pathname)
      @environment  = environment
      @logical_path = logical_path
      @pathname     = pathname
      @__LINE__     = nil

      @_required_paths    = []
      @_dependency_paths  = Set.new
      @_dependency_assets = Set.new([pathname.to_s])
    end

    # Returns the environment path that contains the file.
    #
    # If `app/javascripts` and `app/stylesheets` are in your path, and
    # current file is `app/javascripts/foo/bar.js`, `root_path` would
    # return `app/javascripts`.
    def root_path
      environment.paths.detect { |path| pathname.to_s[path] }
    end

    # Returns logical path without any file extensions.
    #
    #     'app/javascripts/application.js'
    #     # => 'application'
    #
    def logical_path
      @logical_path[/^([^.]+)/, 0]
    end

    # Returns content type of file
    #
    #     'application/javascript'
    #     'text/css'
    #
    def content_type
      environment.content_type_of(pathname)
    end

    # Given a logical path, `resolve` will find and return the fully
    # expanded path. Relative paths will also be resolved. An optional
    # `:content_type` restriction can be supplied to restrict the
    # search.
    #
    #     resolve("foo.js")
    #     # => "/path/to/app/javascripts/foo.js"
    #
    #     resolve("./bar.js")
    #     # => "/path/to/app/javascripts/bar.js"
    #
    def resolve(path, options = {}, &block)
      pathname   = Pathname.new(path)
      attributes = environment.attributes_for(pathname)

      if pathname.absolute?
        pathname

      elsif content_type = options[:content_type]
        content_type = self.content_type if content_type == :self

        if attributes.format_extension
          if content_type != attributes.content_type
            raise ContentTypeMismatch, "#{path} is " +
              "'#{attributes.content_type}', not '#{content_type}'"
          end
        end

        resolve(path) do |candidate|
          if self.content_type == environment.content_type_of(candidate)
            return candidate
          end
        end

        raise FileNotFound, "couldn't find file '#{path}'"
      else
        environment.resolve(path, :base_path => self.pathname.dirname, &block)
      end
    end

    # `depend_on` allows you to state a dependency on a file without
    # including it.
    #
    # This is used for caching purposes. Any changes made to
    # the dependency file with invalidate the cache of the
    # source file.
    def depend_on(path)
      @_dependency_paths << resolve(path).to_s
      nil
    end

    # `depend_on_asset` allows you to state an asset dependency
    # without including it.
    #
    # This is used for caching purposes. Any changes that would
    # invalidate the dependency asset will invalidate the source
    # file. Unlike `depend_on`, this will include recursively include
    # the target asset's dependencies.
    def depend_on_asset(path)
      filename = resolve(path).to_s
      @_dependency_assets << filename
      nil
    end

    # `require_asset` declares `path` as a dependency of the file. The
    # dependency will be inserted before the file and will only be
    # included once.
    #
    # If ERB processing is enabled, you can use it to dynamically
    # require assets.
    #
    #     <%= require_asset "#{framework}.js" %>
    #
    def require_asset(path)
      pathname = resolve(path, :content_type => :self)
      depend_on_asset(pathname)
      @_required_paths << pathname.to_s
      nil
    end

    # Tests if target path is able to be safely required into the
    # current concatenation.
    def asset_requirable?(path)
      pathname = resolve(path)
      content_type = environment.content_type_of(pathname)
      stat = environment.stat(path)
      return false unless stat && stat.file?
      self.content_type.nil? || self.content_type == content_type
    end

    # Reads `path` and runs processors on the file.
    #
    # This allows you to capture the result of an asset and include it
    # directly in another.
    #
    #     <%= evaluate "bar.js" %>
    #
    def evaluate(path, options = {})
      pathname   = resolve(path)
      attributes = environment.attributes_for(pathname)
      processors = options[:processors] || attributes.processors

      if options[:data]
        result = options[:data]
      else
        result = Sprockets::Utils.read_unicode(pathname)
      end

      processors.each do |processor|
        begin
          template = processor.new(pathname.to_s) { result }
          result = template.render(self, {})
        rescue Exception => e
          annotate_exception! e
          raise
        end
      end

      result
    end

    # Returns a Base64-encoded `data:` URI with the contents of the
    # asset at the specified path, and marks that path as a dependency
    # of the current file.
    #
    # Use `asset_data_uri` from ERB with CSS or JavaScript assets:
    #
    #     #logo { background: url(<%= asset_data_uri 'logo.png' %>) }
    #
    #     $('<img>').attr('src', '<%= asset_data_uri 'avatar.jpg' %>')
    #
    def asset_data_uri(path)
      depend_on_asset(path)
      asset  = environment.find_asset(path)
      base64 = Base64.encode64(asset.to_s).gsub(/\s+/, "")
      "data:#{asset.content_type};base64,#{Rack::Utils.escape(base64)}"
    end

    private
      # Annotates exception backtrace with the original template that
      # the exception was raised in.
      def annotate_exception!(exception)
        location = pathname.to_s
        location << ":#{@__LINE__}" if @__LINE__

        exception.extend(Sprockets::EngineError)
        exception.sprockets_annotation = "  (in #{location})"
      end

      def logger
        environment.logger
      end
  end
end
