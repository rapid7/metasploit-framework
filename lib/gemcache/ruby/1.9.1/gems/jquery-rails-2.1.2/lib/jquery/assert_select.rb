module ActionDispatch
  module Assertions
    module SelectorAssertions
      # Selects content from a JQuery response.  Patterned loosely on
      # assert_select_rjs.
      #
      # === Narrowing down
      #
      # With no arguments, asserts that one or more method calls are made.
      #
      # Use the +method+ argument to narrow down the assertion to only
      # statements that call that specific method.
      #
      # Use the +opt+ argument to narrow down the assertion to only statements
      # that pass +opt+ as the first argument.
      #
      # Use the +id+ argument to narrow down the assertion to only statements
      # that invoke methods on the result of using that identifier as a
      # selector.
      #
      # === Using blocks
      #
      # Without a block, +assert_select_jquery_ merely asserts that the
      # response contains one or more statements that match the conditions
      # specified above
      #
      # With a block +assert_select_jquery_ also asserts that the method call
      # passes a javascript escaped string containing HTML.  All such HTML
      # fragments are selected and passed to the block.  Nested assertions are
      # supported.
      #
      # === Examples
      #
      # # asserts that the #notice element is hidden
      # assert_select :hide, '#notice'
      #
      # # asserts that the #cart element is shown with a blind parameter
      # assert_select :show, :blind, '#cart'
      #
      # # asserts that #cart content contains a #current_item
      # assert_select :html, '#cart' do
      #   assert_select '#current_item'
      # end

      PATTERN_HTML  = "\"((\\\\\"|[^\"])*)\""
      PATTERN_UNICODE_ESCAPED_CHAR = /\\u([0-9a-zA-Z]{4})/

      def assert_select_jquery(*args, &block)
        jquery_method = args.first.is_a?(Symbol) ? args.shift : nil
        jquery_opt    = args.first.is_a?(Symbol) ? args.shift : nil
        id            = args.first.is_a?(String) ? args.shift : nil

        pattern = "\\.#{jquery_method || '\\w+'}\\("
        pattern = "#{pattern}['\"]#{jquery_opt}['\"],?\\s*" if jquery_opt
        pattern = "#{pattern}#{PATTERN_HTML}"
        pattern = "(?:jQuery|\\$)\\(['\"]#{id}['\"]\\)#{pattern}" if id

        fragments = []
        response.body.scan(Regexp.new(pattern)).each do |match|
          doc = HTML::Document.new(unescape_js(match.first))
          doc.root.children.each do |child|
            fragments.push child if child.tag?
          end
        end

        if fragments.empty?
          opts = [jquery_method, jquery_opt, id].compact
          flunk "No JQuery call matches #{opts.inspect}"
        end

        if block
          begin
            in_scope, @selected = @selected, fragments
            yield
          ensure
            @selected = in_scope
          end
        end
      end

    private

      # Unescapes a JS string.
      def unescape_js(js_string)
        # js encodes double quotes and line breaks.
        unescaped= js_string.gsub('\"', '"')
        unescaped.gsub!('\\\'', "'")
        unescaped.gsub!(/\\\//, '/')
        unescaped.gsub!('\n', "\n")
        unescaped.gsub!('\076', '>')
        unescaped.gsub!('\074', '<')
        # js encodes non-ascii characters.
        unescaped.gsub!(PATTERN_UNICODE_ESCAPED_CHAR) {|u| [$1.hex].pack('U*')}
        unescaped
      end

    end
  end
end
