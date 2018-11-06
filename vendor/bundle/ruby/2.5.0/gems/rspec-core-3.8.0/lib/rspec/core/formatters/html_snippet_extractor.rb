module RSpec
  module Core
    module Formatters
      # @api private
      #
      # Extracts code snippets by looking at the backtrace of the passed error
      # and applies synax highlighting and line numbers using html.
      class HtmlSnippetExtractor
        # @private
        module NullConverter
          def self.convert(code)
            %Q(#{code}\n<span class="comment"># Install the coderay gem to get syntax highlighting</span>)
          end
        end

        # @private
        module CoderayConverter
          def self.convert(code)
            CodeRay.scan(code, :ruby).html(:line_numbers => false)
          end
        end

        # rubocop:disable Style/ClassVars
        # @private
        @@converter = NullConverter

        begin
          require 'coderay'
          RSpec::Support.require_rspec_core 'formatters/syntax_highlighter'
          RSpec::Core::Formatters::SyntaxHighlighter.attempt_to_add_rspec_terms_to_coderay_keywords
          @@converter = CoderayConverter
          # rubocop:disable Lint/HandleExceptions
        rescue LoadError
          # it'll fall back to the NullConverter assigned above
          # rubocop:enable Lint/HandleExceptions
        end

        # rubocop:enable Style/ClassVars

        # @api private
        #
        # Extract lines of code corresponding to  a backtrace.
        #
        # @param backtrace [String] the backtrace from a test failure
        # @return [String] highlighted code snippet indicating where the test
        #   failure occured
        #
        # @see #post_process
        def snippet(backtrace)
          raw_code, line = snippet_for(backtrace[0])
          highlighted = @@converter.convert(raw_code)
          post_process(highlighted, line)
        end
        # rubocop:enable Style/ClassVars

        # @api private
        #
        # Create a snippet from a line of code.
        #
        # @param error_line [String] file name with line number (i.e.
        #   'foo_spec.rb:12')
        # @return [String] lines around the target line within the file
        #
        # @see #lines_around
        def snippet_for(error_line)
          if error_line =~ /(.*):(\d+)/
            file = Regexp.last_match[1]
            line = Regexp.last_match[2].to_i
            [lines_around(file, line), line]
          else
            ["# Couldn't get snippet for #{error_line}", 1]
          end
        end

        # @api private
        #
        # Extract lines of code centered around a particular line within a
        # source file.
        #
        # @param file [String] filename
        # @param line [Fixnum] line number
        # @return [String] lines around the target line within the file (2 above
        #   and 1 below).
        def lines_around(file, line)
          if File.file?(file)
            lines = File.read(file).split("\n")
            min = [0, line - 3].max
            max = [line + 1, lines.length - 1].min
            selected_lines = []
            selected_lines.join("\n")
            lines[min..max].join("\n")
          else
            "# Couldn't get snippet for #{file}"
          end
        rescue SecurityError
          "# Couldn't get snippet for #{file}"
        end

        # @api private
        #
        # Adds line numbers to all lines and highlights the line where the
        # failure occurred using html `span` tags.
        #
        # @param highlighted [String] syntax-highlighted snippet surrounding the
        #   offending line of code
        # @param offending_line [Fixnum] line where failure occured
        # @return [String] completed snippet
        def post_process(highlighted, offending_line)
          new_lines = []
          highlighted.split("\n").each_with_index do |line, i|
            new_line = "<span class=\"linenum\">#{offending_line + i - 2}</span>#{line}"
            new_line = "<span class=\"offending\">#{new_line}</span>" if i == 2
            new_lines << new_line
          end
          new_lines.join("\n")
        end
      end
    end
  end
end
