# frozen_string_literal: true

module RuboCop
  module Cop
    module Lint
      # Looks for invalid pack/unpack directives with Ruby 3.3.0 some directives
      # that used to not raise errors, now will - context: https://bugs.ruby-lang.org/issues/19150:
      #   * Array#pack now raises ArgumentError for unknown directives
      #   * String#unpack now raises ArgumentError for unknown directives
      #
      # @example
      #   # bad
      #   ```
      #   3.3.0-preview1 :003 > [0x1].pack('<L')
      #   <internal:pack>:8:in `pack': unknown pack directive '<' in '<L' (ArgumentError)
      #   ```
      #
      #   # good
      #   ```
      #   3.3.0-preview1 :001 > [0x1].pack('L<')
      #     => "\x01\x00\x00\x00"
      #   ```
      class DetectInvalidPackDirectives < RuboCop::Cop::Base
        # https://github.com/ruby/ruby/blob/7cfabe1acc55b24fc2c479a87efa71cf74e9e8fc/pack.c#L38
        MODIFIABLE_DIRECTIVES = %w[s S i I l L q Q j J]

        # https://github.com/ruby/ruby/blob/7cfabe1acc55b24fc2c479a87efa71cf74e9e8fc/pack.c#L298
        ACCEPTABLE_DIRECTIVES = %w[U m A B H a A Z b B h H c C s S i I l L q Q j J n N v V f F e E d D g G x X @ % U u m M P p w]

        # @param [RuboCop::AST::SendNode] node Node for the ruby `send` method
        # @return [[RuboCop::AST::Node], raise] offense when an invalid directive is found, or raise if unexpected error found
        def on_send(node)
          _callee, method_name = *node

          return unless %i[pack unpack pack1 unpack1].include?(method_name)

          args = node.arguments
          return if args.empty?

          args.each do |arg|
            next unless string_arg?(arg)

            # if multiline arguments are passed
            if arg.type == :dstr
              idx = []

              pack_directive = arg.children.map do |child|
                if begin_arg?(child)
                  next
                else
                  idx << child.children.first.length
                  child.children.join
                end
              end.join

            # elsif single line arguments are passed
            elsif arg.type == :str
              pack_directive = arg.children.first
            end

            error = validate_directive(pack_directive)
            if error.nil?
              next
            else
              offense_range = get_error_range(arg, error[:index], idx)
              return if offense_range.nil?

              add_offense(offense_range, message: error[:message])
            end
          end
        end

        private

        # Check if the pack directives are valid. See link for pack docs https://apidock.com/ruby/Array/pack
        #
        # Code based on https://github.com/ruby/ruby/blob/6391132c03ac08da0483adb986ff9a54e41f9e14/pack.c#L196
        # adapted into Ruby
        #
        # @param [String] pack_directive The ruby pack/unpack directive to validate
        # @return [Hash,nil] A hash with the message and index that the invalidate directive was found at, or nil.
        def validate_directive(pack_directive)
          # current pointer value
          p = 0

          # end of pointer range
          pend = pack_directive.length

          while p < pend
            explicit_endian = 0
            type_index = p

            # get data type
            type = pack_directive[type_index]
            p += 1

            if type.blank?
              next
            end

            if type == '#'
              p += 1 while p < pend && pack_directive[p] != "\n"
              next
            end

            # Modifiers
            loop do
              case pack_directive[p]
              when '_', '!'
                if MODIFIABLE_DIRECTIVES.include?(type)
                  p += 1
                else
                  return { message: "'#{pack_directive[p]}' allowed only after types #{MODIFIABLE_DIRECTIVES.join}", index: p }
                end
              when '<', '>'
                unless MODIFIABLE_DIRECTIVES.include?(type)
                  return { message: "'#{pack_directive[p]}' allowed only after types #{MODIFIABLE_DIRECTIVES.join}", index: p }
                end

                if explicit_endian != 0
                  return { message: "Can't use both '<' and '>'.", index: p }
                end

                explicit_endian = pack_directive[p]
                p += 1
              else
                break
              end
            end

            # Data length
            if pack_directive[p] == '*'
              p += 1
            elsif pack_directive[p]&.match?(/\d/)
              p += 1 while pack_directive[p]&.match?(/\d/)
            end

            # Check type
            unless ACCEPTABLE_DIRECTIVES.include?(type)
              return { message: "unknown pack directive '#{type}' in '#{pack_directive}'", index: type_index }
            end
          end

          nil
        end

        # Checks if the current node is of type `:str` or `:dstr` - `dstr` being multiline
        #
        # @param [RuboCop::AST::SendNode] node Node for the ruby `send` method
        # @return [TrueClass, FalseClass]
        def string_arg?(node)
          node&.type == :str || node&.type == :dstr
        end

        # Check if the node if of type `:begin`
        #
        # @param [RuboCop::AST::SendNode] node Node for the ruby `send` method
        # @return [TrueClass, FalseClass]
        def begin_arg?(node)
          node.type == :begin
        end

        # Get the range of the offense to more accurately raise offenses against specific directives
        #
        # @param [RuboCop::AST::DstrNode, RuboCop::AST::StrNode ] arg The node that need its range calculated
        # @param [Integer] p The current pointer value
        # @param [Array] idx An array holding to number of indexes for the node
        # @return [Parser::Source::Range] The range of the node value
        def get_error_range(arg, p, idx)
          # Logic for multiline strings
          if arg.type == :dstr
            total = 0
            index = 0

            idx.each_with_index do |idx_length, count|
              if total < p
                total += idx_length
                index = count
              end
            end
            adjusted_index = p - idx[0..(index - 1)].sum

            indexed_arg = arg.children[index]

            if begin_arg?(indexed_arg)
              return nil
            else
              newline_adjustment = indexed_arg.children.first[0..adjusted_index].scan(/[\n\t]/).count
            end

            # If there's opening quotes present, i.e. "a", instead of heredoc which doesn't have preceding opening quotes:
            if indexed_arg.loc.begin
              range_start = indexed_arg.loc.begin.end_pos + (p - adjusted_index)
            else
              expression = processed_source.raw_source[indexed_arg.loc.expression.begin.begin_pos...indexed_arg.loc.expression.end.end_pos]
              if expression[/^\s+/].nil?
                leading_whitespace_size = 0
              else
                leading_whitespace_size = expression[/^\s+/].length
              end
              adjusted_index += leading_whitespace_size
              range_start = indexed_arg.loc.expression.begin_pos + (adjusted_index + newline_adjustment)
            end
          # Logic for single line strings
          else
            newline_adjustment = arg.children.first[0..p].scan(/[\n\t]/).count
            range_start = arg.loc.begin.end_pos + (p + newline_adjustment)
          end

          range_end = range_start + 1

          Parser::Source::Range.new(arg.loc.expression.source_buffer, range_start, range_end)
        end
      end
    end
  end
end
