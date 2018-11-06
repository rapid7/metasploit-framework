# frozen_string_literal: true
module YARD
  module Templates
    module Helpers
      # Helper methods for syntax highlighting.
      module HtmlSyntaxHighlightHelper
        include ModuleHelper

        # Highlights Ruby source
        # @param [String] source the Ruby source code
        # @return [String] the highlighted Ruby source
        def html_syntax_highlight_ruby(source)
          if Parser::SourceParser.parser_type == :ruby
            html_syntax_highlight_ruby_ripper(source)
          else
            html_syntax_highlight_ruby_legacy(source)
          end
        end

        private

        def html_syntax_highlight_ruby_ripper(source)
          resolver = Parser::Ruby::TokenResolver.new(source, object)
          output = String.new("")
          resolver.each do |s, token_obj|
            token_obj = clean_token_object(token_obj)
            output << "<span class='tstring'>" if [:tstring_beg, :regexp_beg].include?(s[0])
            case s.first
            when :nl, :ignored_nl, :sp
              output << h(s[1])
            when :ident, :const
              klass = s.first == :ident ? "id identifier rubyid_#{h(s[1])}" : s.first
              val = token_obj ? link_object(token_obj, s[1]) : h(s[1])
              output << "<span class='#{klass}'>#{val}</span>"
            else
              output << "<span class='#{s.first}'>#{h(s[1])}</span>"
            end
            output << "</span>" if [:tstring_end, :regexp_end].include?(s[0])
          end
          output
        rescue Parser::ParserSyntaxError
          h(source)
        end

        def html_syntax_highlight_ruby_legacy(source)
          tokenlist = Parser::Ruby::Legacy::TokenList.new(source)
          tokenlist.map do |s|
            prettyclass = s.class.class_name.sub(/^Tk/, '').downcase
            prettysuper = s.class.superclass.class_name.sub(/^Tk/, '').downcase

            case s
            when Parser::Ruby::Legacy::RubyToken::TkWhitespace, Parser::Ruby::Legacy::RubyToken::TkUnknownChar
              h s.text
            when Parser::Ruby::Legacy::RubyToken::TkId
              prettyval = h(s.text)
              "<span class='rubyid_#{prettyval} #{prettyclass} #{prettysuper}'>#{prettyval}</span>"
            else
              "<span class='#{prettyclass} #{prettysuper}'>#{h s.text}</span>"
            end
          end.join
        end

        def clean_token_object(token_obj)
          return unless token_obj
          if token_obj == object
            token_obj = nil
          elsif token_obj.is_a?(CodeObjects::MethodObject)
            token_obj = prune_method_listing([token_obj], false).first
          else
            token_obj = run_verifier([token_obj]).first
          end

          token_obj
        end
      end
    end
  end
end
