# frozen_string_literal: true
module YARD
  module Handlers
    module C
      class Base < Handlers::Base
        include YARD::Parser::C
        include HandlerMethods

        # @return [Boolean] whether the handler handles this statement
        def self.handles?(statement, processor)
          processor.globals.cruby_processed_files ||= {}
          processor.globals.cruby_processed_files[processor.file] = true

          src = statement.respond_to?(:declaration) ?
            statement.declaration : statement.source

          handlers.any? do |a_handler|
            statement_class >= statement.class &&
              case a_handler
              when String
                src == a_handler
              when Regexp
                src =~ a_handler
              end
          end
        end

        def self.statement_class(type = nil)
          if type
            @statement_class = type
          else
            (defined?(@statement_class) && @statement_class) || Statement
          end
        end

        # @group Registering objects

        def register_docstring(object, docstring = nil, stmt = nil)
          super(object, docstring, stmt) if docstring
        end

        def register_file_info(object, file = nil, line = nil, comments = nil)
          super(object, file, line, comments) if file
        end

        def register_source(object, source = nil, type = nil)
          super(object, source, type) if source
        end

        def register_visibility(object, visibility = nil)
          super(object, visibility) if visibility
        end

        # @group Looking up Symbol and Var Values

        def symbols
          globals.cruby_symbols ||= {}
        end

        def override_comments
          globals.cruby_override_comments ||= []
        end

        def namespace_for_variable(var)
          return namespaces[var] if namespaces[var]
          var = remove_var_prefix(var)
          var.empty? ? nil : P(var)
        end

        def ensure_variable_defined!(var, max_retries = 1)
          retries = 0
          object = nil

          loop do
            object = namespace_for_variable(var)
            break unless object.is_a?(Proxy)

            raise NamespaceMissingError, object if retries > max_retries
            log.debug "Missing namespace variable #{var} in file `#{parser.file}', moving it to the back of the line."
            parser.parse_remaining_files
            retries += 1
          end

          object
        end

        def namespaces
          globals.cruby_namespaces ||= {}
        end

        def processed_files
          globals.cruby_processed_files ||= {}
        end

        # @group Parsing an Inner Block

        def parse_block(opts = {})
          return if !statement.block || statement.block.empty?
          push_state(opts) do
            parser.process(statement.block)
          end
        end

        # @group Processing other files

        def process_file(file, object)
          file = File.cleanpath(file)
          return if processed_files[file]
          processed_files[file] = file
          begin
            log.debug "Processing embedded call to C source #{file}..."
            globals.ordered_parser.files.delete(file) if globals.ordered_parser
            parser.process(Parser::C::CParser.new(File.read(file), file).parse)
          rescue Errno::ENOENT
            log.warn "Missing source file `#{file}' when parsing #{object}"
          end
        end

        # @endgroup

        private

        def remove_var_prefix(var)
          var.gsub(/^rb_[mc]|^[a-z_]+/, '')
        end
      end
    end
  end
end
