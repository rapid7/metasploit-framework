# frozen_string_literal: true
module YARD
  module Handlers
    module Ruby::Legacy
      # This is the base handler for the legacy parser. To implement a legacy
      # handler, subclass this class.
      #
      # @abstract (see Ruby::Base)
      class Base < Handlers::Base
        # For tokens like TkDEF, TkCLASS, etc.
        include YARD::Parser::Ruby::Legacy::RubyToken

        # @return [Boolean] whether or not a {Parser::Ruby::Legacy::Statement} object should be handled
        #   by this handler.
        def self.handles?(stmt)
          handlers.any? do |a_handler|
            case a_handler
            when String
              stmt.tokens.first.text == a_handler
            when Regexp
              stmt.tokens.to_s =~ a_handler
            else
              a_handler == stmt.tokens.first.class
            end
          end
        end

        # Parses a statement's block with a set of state values. If the
        # statement has no block, nothing happens. A description of state
        # values can be found at {Handlers::Base#push_state}
        #
        # @param [Hash] opts State options
        # @option opts (see Handlers::Base#push_state)
        # @see Handlers::Base#push_state #push_state
        def parse_block(opts = {})
          push_state(opts) do
            if statement.block
              blk = Parser::Ruby::Legacy::StatementList.new(statement.block)
              parser.process(blk)
            end
          end
        end

        def call_params
          if statement.tokens.first.is_a?(TkDEF)
            extract_method_details.last.map(&:first)
          else
            tokens = statement.tokens[1..-1]
            tokval_list(tokens, :attr, :identifier, TkId).map(&:to_s)
          end
        end

        def caller_method
          if statement.tokens.first.is_a?(TkIDENTIFIER)
            statement.tokens.first.text
          elsif statement.tokens.first.is_a?(TkDEF)
            extract_method_details.first
          end
        end

        private

        # Extracts method information for macro expansion only
        #
        # @todo This is a duplicate implementation of {MethodHandler}. Refactor.
        # @return [Array<String,Array<Array<String>>>] the method name followed by method
        #   arguments (name and optional value)
        def extract_method_details
          if statement.tokens.to_s =~ /^def\s+(#{METHODMATCH})(?:(?:\s+|\s*\()(.*)(?:\)\s*$)?)?/m
            meth = $1
            args = $2
            meth.gsub!(/\s+/, '')
            args = tokval_list(Parser::Ruby::Legacy::TokenList.new(args), :all)
            args.map! {|a| k, v = *a.split('=', 2); [k.strip, (v ? v.strip : nil)] } if args
            meth = $` if meth =~ /(?:#{NSEPQ}|#{CSEPQ})([^#{NSEP}#{CSEPQ}]+)$/
            [meth, args]
          end
        end

        # The string value of a token. For example, the return value for the symbol :sym
        # would be :sym. The return value for a string +"foo #{ bar}"+ would be the literal
        # +"foo #{ bar}"+ without any interpolation. The return value of the identifier
        # 'test' would be the same value: 'test'. Here is a list of common types and
        # their return values:
        #
        # @example
        #   tokval(TokenList.new('"foo"').first) => "foo"
        #   tokval(TokenList.new(':foo').first) => :foo
        #   tokval(TokenList.new('CONSTANT').first, RubyToken::TkId) => "CONSTANT"
        #   tokval(TokenList.new('identifier').first, RubyToken::TkId) => "identifier"
        #   tokval(TokenList.new('3.25').first) => 3.25
        #   tokval(TokenList.new('/xyz/i').first) => /xyz/i
        #
        # @param [Token] token The token of the class
        #
        # @param [Array<Class<Token>>, Symbol] accepted_types
        #   The allowed token types that this token can be. Defaults to [{TkVal}].
        #   A list of types would be, for example, [+TkSTRING+, +TkSYMBOL+], to return
        #   the token's value if it is either of those types. If +TkVal+ is accepted,
        #   +TkNode+ is also accepted.
        #
        #   Certain symbol keys are allowed to specify multiple types in one fell swoop.
        #   These symbols are:
        #     :string       => +TkSTRING+, +TkDSTRING+, +TkDXSTRING+ and +TkXSTRING+
        #     :attr         => +TkSYMBOL+ and +TkSTRING+
        #     :identifier   => +TkIDENTIFIER, +TkFID+ and +TkGVAR+.
        #     :number       => +TkFLOAT+, +TkINTEGER+
        #
        # @return [Object] if the token is one of the accepted types, in its real value form.
        #   It should be noted that identifiers and constants are kept in String form.
        # @return [nil] if the token is not any of the specified accepted types
        def tokval(token, *accepted_types)
          accepted_types = [TkVal] if accepted_types.empty?
          accepted_types.push(TkNode) if accepted_types.include? TkVal

          if accepted_types.include?(:attr)
            accepted_types.push(TkSTRING, TkSYMBOL)
          end

          if accepted_types.include?(:string)
            accepted_types.push(TkSTRING, TkDSTRING, TkXSTRING, TkDXSTRING)
          end

          if accepted_types.include?(:identifier)
            accepted_types.push(TkIDENTIFIER, TkFID, TkGVAR)
          end

          if accepted_types.include?(:number)
            accepted_types.push(TkFLOAT, TkINTEGER)
          end

          return unless accepted_types.any? {|t| t === token }

          case token
          when TkSTRING, TkDSTRING, TkXSTRING, TkDXSTRING
            token.text[1..-2]
          when TkSYMBOL
            token.text[1..-1].to_sym
          when TkFLOAT
            token.text.to_f
          when TkINTEGER
            token.text.to_i
          when TkREGEXP
            token.text =~ %r{\A/(.+)/([^/])\Z}
            Regexp.new($1, $2)
          when TkTRUE
            true
          when TkFALSE
            false
          when TkNIL
            nil
          else
            token.text
          end
        end

        # Returns a list of symbols or string values from a statement.
        # The list must be a valid comma delimited list, and values
        # will only be returned to the end of the list only.
        #
        # Example:
        #   attr_accessor :a, 'b', :c, :d => ['a', 'b', 'c', 'd']
        #   attr_accessor 'a', UNACCEPTED_TYPE, 'c' => ['a', 'c']
        #
        # The tokval list of a {Parser::Ruby::Legacy::TokenList} of the above
        # code would be the {#tokval} value of :a, 'b',
        # :c and :d.
        #
        # It should also be noted that this function stops immediately at
        # any ruby keyword encountered:
        #   "attr_accessor :a, :b, :c if x == 5"  => ['a', 'b', 'c']
        #
        # @param [TokenList] tokenlist The list of tokens to process.
        # @param [Array<Class<Token>>] accepted_types passed to {#tokval}
        # @return [Array<String>] the list of tokvalues in the list.
        # @return [Array<EMPTY>] if there are no symbols or Strings in the list
        # @see #tokval
        def tokval_list(tokenlist, *accepted_types)
          return [] unless tokenlist
          out = [[]]
          parencount = 0
          beforeparen = 0
          needcomma = false
          seen_comma = true
          tokenlist.each do |token|
            tokval = accepted_types == [:all] ? token.text : tokval(token, *accepted_types)
            parencond = !out.last.empty? && !tokval.nil?
            # puts "#{seen_comma.inspect} #{parencount} #{token.class.class_name} #{out.inspect}"
            case token
            when TkCOMMA
              if parencount == 0
                out << [] unless out.last.empty?
                needcomma = false
                seen_comma = true
              elsif parencond
                out.last << token.text
              end
            when TkLPAREN
              if seen_comma
                beforeparen += 1
              else
                parencount += 1
                out.last << token.text if parencond
              end
            when TkRPAREN
              if beforeparen > 0
                beforeparen -= 1
              else
                out.last << token.text if parencount > 0 && !tokval.nil?
                parencount -= 1
              end
            when TkLBRACE, TkLBRACK, TkDO
              parencount += 1
              out.last << token.text unless tokval.nil?
            when TkRBRACE, TkRBRACK, TkEND
              out.last << token.text unless tokval.nil?
              parencount -= 1
            else
              break if TkKW === token && ![TkTRUE, TkFALSE, TkSUPER, TkSELF, TkNIL].include?(token.class)

              seen_comma = false unless TkWhitespace === token
              if parencount == 0
                next if needcomma
                next if TkWhitespace === token
                if !tokval.nil?
                  out.last << tokval
                else
                  out.last.clear
                  needcomma = true
                end
              elsif parencond
                needcomma = true
                out.last << token.text
              end
            end

            break if beforeparen == 0 && parencount < 0
          end
          # Flatten any single element lists
          out.map {|e| e.empty? ? nil : (e.size == 1 ? e.pop : e.flatten.join) }.compact
        end
      end
    end
  end
end
