module RSpec
  module Core
    module Formatters
      # @private
      # Provides terminal syntax highlighting of code snippets
      # when coderay is available.
      class SyntaxHighlighter
        def initialize(configuration)
          @configuration = configuration
        end

        def highlight(lines)
          implementation.highlight_syntax(lines)
        end

        # rubocop:disable Lint/RescueException
        # rubocop:disable Lint/HandleExceptions
        def self.attempt_to_add_rspec_terms_to_coderay_keywords
          CodeRay::Scanners::Ruby::Patterns::IDENT_KIND.add(%w[
            describe context
            it specify
            before after around
            let subject
            expect allow
          ], :keyword)
        rescue Exception
          # Mutating CodeRay's contants like this is not a public API
          # and might not always work. If we cannot add our keywords
          # to CodeRay it is not a big deal and not worth raising an
          # error over, so we ignore it.
        end
      # rubocop:enable Lint/HandleExceptions
      # rubocop:enable Lint/RescueException

      private

        if RSpec::Support::OS.windows?
          # :nocov:
          def implementation
            WindowsImplementation
          end
          # :nocov:
        else
          def implementation
            return color_enabled_implementation if @configuration.color_enabled?
            NoSyntaxHighlightingImplementation
          end
        end

        def color_enabled_implementation
          @color_enabled_implementation ||= begin
            require 'coderay'
            self.class.attempt_to_add_rspec_terms_to_coderay_keywords
            CodeRayImplementation
          rescue LoadError
            NoSyntaxHighlightingImplementation
          end
        end

        # @private
        module CodeRayImplementation
          RESET_CODE = "\e[0m"

          def self.highlight_syntax(lines)
            highlighted = begin
              CodeRay.encode(lines.join("\n"), :ruby, :terminal)
            rescue Support::AllExceptionsExceptOnesWeMustNotRescue
              return lines
            end

            highlighted.split("\n").map do |line|
              line.sub(/\S/) { |char| char.insert(0, RESET_CODE) }
            end
          end
        end

        # @private
        module NoSyntaxHighlightingImplementation
          def self.highlight_syntax(lines)
            lines
          end
        end

        # @private
        # Not sure why, but our code above (and/or coderay itself) does not work
        # on Windows, so we disable the feature on Windows.
        WindowsImplementation = NoSyntaxHighlightingImplementation
      end
    end
  end
end
