# frozen_string_literal: true
module YARD
  module Server
    # A router class implements the logic used to recognize a request for a specific
    # URL and run specific {Commands::Base commands}.
    #
    # == Subclassing Notes
    # To create a custom router, subclass this class and pass it into the adapter
    # options through {Adapter#initialize} or by directly modifying {Adapter#router}.
    #
    # The most general customization is to change the URL prefixes recognized by
    # routing, which can be done by overriding {#docs_prefix}, {#list_prefix},
    # {#static_prefix}, and {#search_prefix}.
    #
    # == Implementing Custom Caching
    # By default, the Router class performs static disk-based caching on all
    # requests through the +#check_static_cache+. To override this behaviour,
    # or create your own caching mechanism, mixin your own custom module with
    # this method implemented as per {StaticCaching#check_static_cache}.
    #
    # @example Creating a subclassed router
    #   # Adds 'my' to all routing prefixes
    #   class MyRouter < YARD::Server::Router
    #     def docs_prefix; 'mydocs' end
    #     def list_prefix; 'mylist' end
    #     def static_prefix; 'mystatic' end
    #     def search_prefix; 'mysearch' end
    #   end
    #
    #   # Using it:
    #   WebrickAdapter.new(libraries, :router => MyRouter).start
    class Router
      include StaticCaching
      include Commands

      # @return [Adapter Dependent] the request data coming in with the routing
      attr_accessor :request

      # @return [Adapter] the adapter used by the router
      attr_accessor :adapter

      # Creates a new router for a specific adapter
      #
      # @param [Adapter] adapter the adapter to route requests to
      def initialize(adapter)
        self.adapter = adapter
      end

      # Perform routing on a specific request, serving the request as a static
      # file through {Commands::RootRequestCommand} if no route is found.
      #
      # @param [Adapter Dependent] request the request object
      # @return [Array(Numeric,Hash,Array)] the Rack-style server response data
      def call(request)
        self.request = request
        result = check_static_cache || route
        result ? result : RootRequestCommand.new(adapter.options).call(request)
      end

      # @group Route Prefixes

      # @return [String] the URI prefix for all object documentation requests
      def docs_prefix; 'docs' end

      # @return [String] the URI prefix for all class/method/file list requests
      def list_prefix; 'list' end

      # @return [String] the URI prefix for all search requests
      def search_prefix; 'search' end

      # @return [String] the URI prefix for all static assets (templates)
      def static_prefix; 'static' end

      # @group Routing Methods

      # @return [Array(LibraryVersion, Array<String>)] the library followed
      #   by the rest of the path components in the request path. LibraryVersion
      #   will be nil if no matching library was found.
      def parse_library_from_path(paths)
        return [adapter.libraries.values.first.first, paths] if adapter.options[:single_library]
        library = nil
        paths = paths.dup
        libs = adapter.libraries[paths.first]
        if libs
          paths.shift
          library = libs.find {|l| l.version == paths.first }
          if library
            request.version_supplied = true if request
            paths.shift
          else # use the last lib in the list
            request.version_supplied = false if request
            library = libs.last
          end
        end
        [library, paths]
      end

      protected

      # Performs routing algorithm to find which prefix is called, first
      # parsing out library name/version information.
      #
      # @return [Array(Numeric,Hash,Array<String>)] the Rack-style response
      # @return [nil] if no route is matched
      def route(path = request.path_info)
        path = path.gsub(%r{//+}, '/').gsub(%r{^/|/$}, '')
        return route_index if path.empty? || path == docs_prefix
        case path
        when %r{^(#{docs_prefix}|#{list_prefix}|#{search_prefix}|#{static_prefix})(/.*|$)}
          prefix = $1
          paths = $2.gsub(%r{^/|/$}, '').split('/')
          library, paths = *parse_library_from_path(paths)
          return unless library
          return case prefix
                 when docs_prefix;   route_docs(library, paths)
                 when list_prefix;   route_list(library, paths)
                 when search_prefix; route_search(library, paths)
                 when static_prefix; route_static(library, paths)
                 end
        end
        nil
      end

      # Routes requests from {#docs_prefix} and calls the appropriate command
      # @param [LibraryVersion] library the library to route for
      # @param [Array<String>] paths path components (split by '/')
      # @return (see #route)
      def route_docs(library, paths)
        return route_index if library.nil?
        case paths.first
        when "frames"
          paths.shift
          cmd = DisplayObjectCommand
        when "file"
          paths.shift
          cmd = DisplayFileCommand
        else
          cmd = DisplayObjectCommand
        end
        cmd = cmd.new(final_options(library, paths))
        cmd.call(request)
      end

      # Routes for the index of a library / multiple libraries
      # @return (see #route)
      def route_index
        if adapter.options[:single_library]
          route_docs(adapter.libraries.values.first.first, [])
        else
          LibraryIndexCommand.new(adapter.options.merge(:path => '')).call(request)
        end
      end

      # Routes requests from {#list_prefix} and calls the appropriate command
      # @param (see #route_docs)
      # @return (see #route_docs)
      def route_list(library, paths)
        return if paths.empty?
        ListCommand.new(final_options(library, paths)).call(request)
      end

      # Routes requests from {#search_prefix} and calls the appropriate command
      # @param (see #route_docs)
      # @return (see #route_docs)
      def route_search(library, paths)
        return unless paths.empty?
        SearchCommand.new(final_options(library, paths)).call(request)
      end

      def route_static(library, paths)
        StaticFileCommand.new(final_options(library, paths)).call(request)
      end

      # @group Utility Methods

      # Adds extra :library/:path option keys to the adapter options.
      # Use this method when passing options to a command.
      #
      # @param (see #route_docs)
      # @return [Hash] finalized options
      def final_options(library, paths)
        path = File.cleanpath(paths.join('/')).gsub(%r{^(\.\./)+}, '')
        adapter.options.merge(:library => library, :path => path)
      end
    end
  end
end
