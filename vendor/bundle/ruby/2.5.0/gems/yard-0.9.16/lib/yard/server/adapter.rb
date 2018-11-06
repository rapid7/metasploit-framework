# frozen_string_literal: true
module YARD
  module Server
    # Short circuits a request by raising an error. This exception is caught
    # by {Commands::Base#call} to immediately end a request and return a response.
    class FinishRequest < RuntimeError; end

    # Raises an error if a resource is not found. This exception is caught by
    # {Commands::Base#call} to immediately end a request and return a 404 response
    # code. If a message is provided, the body is set to the exception message.
    class NotFoundError < RuntimeError; end

    # This class implements the bridge between the {Router} and the server
    # backend for a specific server type. YARD implements concrete adapters
    # for WEBrick and Rack respectively, though other adapters can be made
    # for other server architectures.
    #
    # == Subclassing Notes
    # To create a concrete adapter class, implement the {#start} method to
    # initiate the server backend.
    #
    # @abstract
    class Adapter
      # @return [String] the location where static files are located, if any.
      #   To set this field on initialization, pass +:DocumentRoot+ to the
      #   +server_opts+ argument in {#initialize}
      attr_accessor :document_root

      # @return [Hash{String=>Array<LibraryVersion>}] a map of libraries.
      # @see LibraryVersion LibraryVersion for information on building a list of libraries
      # @see #add_library
      attr_accessor :libraries

      # @return [Hash] options passed and processed by adapters. The actual
      #   options mostly depend on the adapters themselves.
      attr_accessor :options

      # @return [Hash] a set of options to pass to the server backend. Note
      #   that +:DocumentRoot+ also sets the {#document_root}.
      attr_accessor :server_options

      # @return [Router] the router object used to route URLs to commands
      attr_accessor :router

      # Performs any global initialization for the adapter.
      # @note If you subclass this method, make sure to call +super+.
      # @return [void]
      def self.setup
        Templates::Template.extra_includes |= [YARD::Server::DocServerHelper]
        Templates::Engine.template_paths |= [File.dirname(__FILE__) + '/templates']
      end

      # Performs any global shutdown procedures for the adapter.
      # @note If you subclass this method, make sure to call +super+.
      # @return [void]
      def self.shutdown
        Templates::Template.extra_includes -= [YARD::Server::DocServerHelper]
        Templates::Engine.template_paths -= [File.dirname(__FILE__) + '/templates']
      end

      # Creates a new adapter object
      #
      # @param [Hash{String=>Array<LibraryVersion>}] libs a list of libraries,
      #   see {#libraries} for formulating this list.
      # @param [Hash] opts extra options to pass to the adapter
      # @option opts [Class] :router (Router) the router class to initialize as the
      #   adapter's router.
      # @option opts [Boolean] :caching (false) whether or not caching is enabled
      # @option opts [Boolean] :single_library (false) whether to server documentation
      #   for a single or multiple libraries (changes URL structure)
      def initialize(libs, opts = {}, server_opts = {})
        self.class.setup
        self.libraries = libs
        self.options = opts
        self.server_options = server_opts
        self.document_root = server_options[:DocumentRoot]
        self.router = (options[:router] || Router).new(self)
        options[:adapter] = self
        log.debug "Serving libraries using #{self.class}: #{libraries.keys.join(', ')}"
        log.debug "Caching on" if options[:caching]
        log.debug "Document root: #{document_root}" if document_root
      end

      # Adds a library to the {#libraries} mapping for a given library object.
      # @example Adding a new library to an adapter
      #   adapter.add_library LibraryVersion.new('mylib', '1.0', '/path/to/.yardoc')
      # @param [LibraryVersion] library a library to add
      def add_library(library)
        libraries[library.name] ||= []
        libraries[library.name] |= [library]
      end

      # Implement this method to connect your adapter to your server.
      # @abstract
      def start
        raise NotImplementedError
      end
    end
  end
end
