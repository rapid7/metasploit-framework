module RSpec
  module Rails
    module Matchers
      # Matcher for template rendering.
      module RenderTemplate
        # @private
        class RenderTemplateMatcher < RSpec::Matchers::BuiltIn::BaseMatcher
          def initialize(scope, expected, message = nil)
            @expected = Symbol === expected ? expected.to_s : expected
            @message = message
            @scope = scope
            @redirect_is = nil
          end

          # @api private
          def matches?(*)
            match_check = match_unless_raises ActiveSupport::TestCase::Assertion do
              @scope.assert_template expected, @message
            end
            check_redirect unless match_check
            match_check
          end

          # Uses normalize_argument_to_redirection to find and format
          # the redirect location. normalize_argument_to_redirection is private
          # in ActionDispatch::Assertions::ResponseAssertions so we call it
          # here using #send. This will keep the error message format consistent
          # @api private
          def check_redirect
            response = @scope.response
            return unless response.respond_to?(:redirect?) && response.redirect?
            @redirect_is = @scope.send(:normalize_argument_to_redirection, response.location)
          end

          # @api private
          def failure_message
            if @redirect_is
              rescued_exception.message[/(.*?)( but|$)/, 1] +
                " but was a redirect to <#{@redirect_is}>"
            else
              rescued_exception.message
            end
          end

          # @api private
          def failure_message_when_negated
            "expected not to render #{expected.inspect}, but did"
          end
        end

        # Delegates to `assert_template`.
        #
        # @example
        #     expect(response).to have_rendered("new")
        def have_rendered(options, message = nil)
          RenderTemplateMatcher.new(self, options, message)
        end

        alias_method :render_template, :have_rendered
      end
    end
  end
end
