# frozen_string_literal: true
require 'ostruct'

module YARD
  module Handlers
    # Iterates over all statements in a file and delegates them to the
    # {Handlers::Base} objects that are registered to handle the statement.
    #
    # This class is passed to each handler and keeps overall processing state.
    # For example, if the {#visibility} is set in a handler, all following
    # statements will have access to this state. This allows "public",
    # "protected" and "private" statements to be handled in classes and modules.
    # In addition, the {#namespace} can be set during parsing to control
    # where objects are being created from. You can also access extra stateful
    # properties that any handler can set during the duration of the post
    # processing of a file from {#extra_state}. If you need to access state
    # across different files, look at {#globals}.
    #
    # @see Handlers::Base
    class Processor
      class << self
        # Registers a new namespace for handlers of the given type.
        # @since 0.6.0
        def register_handler_namespace(type, ns)
          namespace_for_handler[type] = ns
        end

        # @return [Hash] a list of registered parser type extensions
        # @private
        # @since 0.6.0
        attr_reader :namespace_for_handler
        undef namespace_for_handler
        def namespace_for_handler; @@parser_type_extensions ||= {} end
      end

      register_handler_namespace :ruby, Ruby
      register_handler_namespace :ruby18, Ruby::Legacy
      register_handler_namespace :c, C

      # @return [String] the filename
      attr_accessor :file

      # @return [CodeObjects::NamespaceObject] the current namespace
      attr_accessor :namespace

      # @return [Symbol] the current visibility (public, private, protected)
      attr_accessor :visibility

      # @return [Symbol] the current scope (class, instance)
      attr_accessor :scope

      # @return [CodeObjects::Base, nil] unlike the namespace, the owner
      #   is a non-namespace object that should be stored between statements.
      #   For instance, when parsing a method body, the {CodeObjects::MethodObject}
      #   is set as the owner, in case any extra method information is processed.
      attr_accessor :owner

      # @return [Symbol] the parser type (:ruby, :ruby18, :c)
      attr_accessor :parser_type

      # Handlers can share state for the entire post processing stage through
      # this attribute. Note that post processing stage spans multiple files.
      # To share state only within a single file, use {#extra_state}
      #
      # @example Sharing state among two handlers
      #   class Handler1 < YARD::Handlers::Ruby::Base
      #     handles :class
      #     process { globals.foo = :bar }
      #   end
      #
      #   class Handler2 < YARD::Handlers::Ruby::Base
      #     handles :method
      #     process { puts globals.foo }
      #   end
      # @return [OpenStruct] global shared state for post-processing stage
      # @see #extra_state
      attr_accessor :globals

      # Share state across different handlers inside of a file.
      # This attribute is similar to {#visibility}, {#scope}, {#namespace}
      # and {#owner}, in that they all maintain state across all handlers
      # for the entire source file. Use this attribute to store any data
      # your handler might need to save during the parsing of a file. If
      # you need to save state across files, see {#globals}.
      #
      # @return [OpenStruct] an open structure that can store arbitrary data
      # @see #globals
      attr_accessor :extra_state

      # Creates a new Processor for a +file+.
      # @param [Parser::SourceParser] parser the parser used to initialize the processor
      def initialize(parser)
        @file = parser.file || "(stdin)"
        @namespace = YARD::Registry.root
        @visibility = :public
        @scope = :instance
        @owner = @namespace
        @parser_type = parser.parser_type
        @handlers_loaded = {}
        @globals = parser.globals || OpenStruct.new
        @extra_state = OpenStruct.new
        load_handlers
      end

      # Processes a list of statements by finding handlers to process each
      # one.
      #
      # @param [Array] statements a list of statements
      # @return [void]
      def process(statements)
        statements.each_with_index do |stmt, _index|
          find_handlers(stmt).each do |handler|
            begin
              handler.new(self, stmt).process
            rescue HandlerAborted
              log.debug "#{handler} cancelled from #{caller.last}"
              log.debug "\tin file '#{file}':#{stmt.line}:\n\n" + stmt.show + "\n"
            rescue NamespaceMissingError => missingerr
              log.warn "The #{missingerr.object.type} #{missingerr.object.path} has not yet been recognized.\n" \
                       "If this class/method is part of your source tree, this will affect your documentation results.\n" \
                       "You can correct this issue by loading the source file for this object before `#{file}'\n"
            rescue Parser::UndocumentableError => undocerr
              log.warn "in #{handler}: Undocumentable #{undocerr.message}\n" \
                       "\tin file '#{file}':#{stmt.line}:\n\n" + stmt.show + "\n"
            rescue => e
              log.error "Unhandled exception in #{handler}:\n" \
                        "  in `#{file}`:#{stmt.line}:\n\n#{stmt.show}\n"
              log.backtrace(e)
            end
          end
        end
      end

      # Continue parsing the remainder of the files in the +globals.ordered_parser+
      # object. After the remainder of files are parsed, processing will continue
      # on the current file.
      #
      # @return [void]
      # @see Parser::OrderedParser
      def parse_remaining_files
        if globals.ordered_parser
          globals.ordered_parser.parse
          log.debug("Re-processing #{@file}...")
        end
      end

      # Searches for all handlers in {Base.subclasses} that match the +statement+
      #
      # @param statement the statement object to match.
      # @return [Array<Base>] a list of handlers to process the statement with.
      def find_handlers(statement)
        Base.subclasses.find_all do |handler|
          handler_base_class > handler &&
            (handler.namespace_only? ? owner.is_a?(CodeObjects::NamespaceObject) : true) &&
            handles?(handler, statement)
        end
      end

      private

      def handles?(handler, statement)
        return false unless handler.matches_file?(file)
        if handler.method(:handles?).arity == 1
          handler.handles?(statement)
        elsif [-1, 2].include?(handler.method(:handles?).arity)
          handler.handles?(statement, self)
        end
      end

      # Returns the handler base class
      # @return [Base] the base class
      def handler_base_class
        handler_base_namespace.const_get(:Base)
      end

      # The module holding the handlers to be loaded
      #
      # @return [Module] the module containing the handlers depending on
      #   {#parser_type}.
      def handler_base_namespace
        self.class.namespace_for_handler[parser_type]
      end

      # Loads handlers from {#handler_base_namespace}. This ensures that
      # Ruby1.9 handlers are never loaded into 1.8; also lowers the amount
      # of modules that are loaded
      # @return [void]
      def load_handlers
        return if @handlers_loaded[parser_type]
        handler_base_namespace.constants.each do |c|
          const = handler_base_namespace.const_get(c)
          unless Handlers::Base.subclasses.include?(const)
            Handlers::Base.subclasses << const
          end
        end
        @handlers_loaded[parser_type] = true
      end
    end
  end
end
