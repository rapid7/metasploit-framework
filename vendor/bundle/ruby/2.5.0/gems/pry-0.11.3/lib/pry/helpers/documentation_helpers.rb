class Pry
  module Helpers

    # This class contains methods useful for extracting
    # documentation from methods and classes.
    module DocumentationHelpers

      module_function

      def process_rdoc(comment)
        comment = comment.dup
        comment.gsub(/<code>(?:\s*\n)?(.*?)\s*<\/code>/m) { CodeRay.scan($1, :ruby).term }.
          gsub(/<em>(?:\s*\n)?(.*?)\s*<\/em>/m) { "\e[1m#{$1}\e[0m" }.
          gsub(/<i>(?:\s*\n)?(.*?)\s*<\/i>/m) { "\e[1m#{$1}\e[0m" }.
          gsub(/<tt>(?:\s*\n)?(.*?)\s*<\/tt>/m) { CodeRay.scan($1, :ruby).term }.
          gsub(/\B\+(\w+?)\+\B/)  { "\e[32m#{$1}\e[0m" }.
          gsub(/((?:^[ \t]+.+(?:\n+|\Z))+)/)  { CodeRay.scan($1, :ruby).term }.
          gsub(/`(?:\s*\n)?([^\e]*?)\s*`/) { "`#{CodeRay.scan($1, :ruby).term}`" }
      end

      def process_yardoc_tag(comment, tag)
        in_tag_block = nil
        comment.lines.map do |v|
          if in_tag_block && v !~ /^\S/
            Pry::Helpers::Text.strip_color Pry::Helpers::Text.strip_color(v)
          elsif in_tag_block
            in_tag_block = false
            v
          else
            in_tag_block = true if v =~ /^@#{tag}/
            v
          end
        end.join
      end

      def process_yardoc(comment)
        yard_tags = ["param", "return", "option", "yield", "attr", "attr_reader", "attr_writer",
                     "deprecate", "example", "raise"]
        (yard_tags - ["example"]).inject(comment) { |a, v| process_yardoc_tag(a, v) }.
          gsub(/^@(#{yard_tags.join("|")})/) { "\e[33m#{$1}\e[0m" }
      end

      def process_comment_markup(comment)
        process_yardoc process_rdoc(comment)
      end

      # @param [String] code
      # @return [String]
      def strip_comments_from_c_code(code)
        code.sub(/\A\s*\/\*.*?\*\/\s*/m, '')
      end

      # Given a string that makes up a comment in a source-code file parse out the content
      # that the user is intended to read. (i.e. without leading indentation, #-characters
      # or shebangs)
      #
      # @param [String] comment
      # @return [String]
      def get_comment_content(comment)
        comment = comment.dup
        # Remove #!/usr/bin/ruby
        comment.gsub!(/\A\#!.*$/, '')
        # Remove leading empty comment lines
        comment.gsub!(/\A\#+?$/, '')
        comment.gsub!(/^\s*#/, '')
        strip_leading_whitespace(comment)
      end

      # @param [String] text
      # @return [String]
      def strip_leading_whitespace(text)
        Pry::Helpers::CommandHelpers.unindent(text)
      end
    end
  end
end
