# The following code inspired and modified from Rails' `assert_response`:
#
#   https://github.com/rails/rails/blob/master/actionpack/lib/action_dispatch/testing/assertions/response.rb#L22-L38
#
# Thank you to all the Rails devs who did the heavy lifting on this!

module RSpec
  module Rails
    module Matchers
      # Namespace for various implementations of `have_http_status`.
      #
      # @api private
      module HaveHttpStatus
        # Instantiates an instance of the proper matcher based on the provided
        # `target`.
        #
        # @param target [Object] expected http status or code
        # @return response matcher instance
        def self.matcher_for_status(target)
          if GenericStatus.valid_statuses.include?(target)
            GenericStatus.new(target)
          elsif Symbol === target
            SymbolicStatus.new(target)
          else
            NumericCode.new(target)
          end
        end

        # @api private
        # Conversion function to coerce the provided object into an
        # `ActionDispatch::TestResponse`.
        #
        # @param obj [Object] object to convert to a response
        # @return [ActionDispatch::TestResponse]
        def as_test_response(obj)
          if ::ActionDispatch::Response === obj
            ::ActionDispatch::TestResponse.from_response(obj)
          elsif ::ActionDispatch::TestResponse === obj
            obj
          elsif obj.respond_to?(:status_code) && obj.respond_to?(:response_headers)
            # Acts As Capybara Session
            # Hack to support `Capybara::Session` without having to load
            # Capybara or catch `NameError`s for the undefined constants
            obj = ActionDispatch::Response.new.tap do |resp|
              resp.status  = obj.status_code
              resp.headers.clear
              resp.headers.merge!(obj.response_headers)
              resp.body    = obj.body
              resp.request = ActionDispatch::Request.new({})
            end
            ::ActionDispatch::TestResponse.from_response(obj)
          else
            raise TypeError, "Invalid response type: #{obj}"
          end
        end
        module_function :as_test_response

        # @return [String, nil] a formatted failure message if
        #   `@invalid_response` is present, `nil` otherwise
        def invalid_response_type_message
          return unless @invalid_response
          "expected a response object, but an instance of " \
          "#{@invalid_response.class} was received"
        end

        # @api private
        # Provides an implementation for `have_http_status` matching against
        # numeric http status codes.
        #
        # Not intended to be instantiated directly.
        #
        # @example
        #   expect(response).to have_http_status(404)
        #
        # @see RSpec::Rails::Matchers.have_http_status
        class NumericCode < RSpec::Matchers::BuiltIn::BaseMatcher
          include HaveHttpStatus

          def initialize(code)
            @expected = code.to_i
            @actual = nil
            @invalid_response = nil
          end

          # @param [Object] response object providing an http code to match
          # @return [Boolean] `true` if the numeric code matched the `response` code
          def matches?(response)
            test_response = as_test_response(response)
            @actual = test_response.response_code.to_i
            expected == @actual
          rescue TypeError => _ignored
            @invalid_response = response
            false
          end

          # @return [String]
          def description
            "respond with numeric status code #{expected}"
          end

          # @return [String] explaining why the match failed
          def failure_message
            invalid_response_type_message ||
            "expected the response to have status code #{expected.inspect}" \
              " but it was #{actual.inspect}"
          end

          # @return [String] explaining why the match failed
          def failure_message_when_negated
            invalid_response_type_message ||
            "expected the response not to have status code " \
            "#{expected.inspect} but it did"
          end
        end

        # @api private
        # Provides an implementation for `have_http_status` matching against
        # Rack symbol http status codes.
        #
        # Not intended to be instantiated directly.
        #
        # @example
        #   expect(response).to have_http_status(:created)
        #
        # @see RSpec::Rails::Matchers.have_http_status
        # @see https://github.com/rack/rack/blob/master/lib/rack/utils.rb `Rack::Utils::SYMBOL_TO_STATUS_CODE`
        class SymbolicStatus < RSpec::Matchers::BuiltIn::BaseMatcher
          include HaveHttpStatus

          def initialize(status)
            @expected_status = status
            @actual = nil
            @invalid_response = nil
            set_expected_code!
          end

          # @param [Object] response object providing an http code to match
          # @return [Boolean] `true` if Rack's associated numeric HTTP code matched
          #   the `response` code
          def matches?(response)
            test_response = as_test_response(response)
            @actual = test_response.response_code
            expected == @actual
          rescue TypeError => _ignored
            @invalid_response = response
            false
          end

          # @return [String]
          def description
            "respond with status code #{pp_expected}"
          end

          # @return [String] explaining why the match failed
          def failure_message
            invalid_response_type_message ||
            "expected the response to have status code #{pp_expected} but it" \
              " was #{pp_actual}"
          end

          # @return [String] explaining why the match failed
          def failure_message_when_negated
            invalid_response_type_message ||
            "expected the response not to have status code #{pp_expected} " \
              "but it did"
          end

          # The initialized expected status symbol
          attr_reader :expected_status
          private :expected_status

        private

          # @return [Symbol] representing the actual http numeric code
          def actual_status
            return unless actual
            @actual_status ||= compute_status_from(actual)
          end

          # Reverse lookup of the Rack status code symbol based on the numeric
          # http code
          #
          # @param code [Fixnum] http status code to look up
          # @return [Symbol] representing the http numeric code
          def compute_status_from(code)
            status, _ = Rack::Utils::SYMBOL_TO_STATUS_CODE.find do |_, c|
              c == code
            end
            status
          end

          # @return [String] pretty format the actual response status
          def pp_actual
            pp_status(actual_status, actual)
          end

          # @return [String] pretty format the expected status and associated code
          def pp_expected
            pp_status(expected_status, expected)
          end

          # @return [String] pretty format the actual response status
          def pp_status(status, code)
            if status
              "#{status.inspect} (#{code})"
            else
              code.to_s
            end
          end

          # Sets `expected` to the numeric http code based on the Rack
          # `expected_status` status
          #
          # @see Rack::Utils::SYMBOL_TO_STATUS_CODE
          # @raise [ArgumentError] if an associated code could not be found
          def set_expected_code!
            @expected ||=
              Rack::Utils::SYMBOL_TO_STATUS_CODE.fetch(expected_status) do
                raise ArgumentError,
                      "Invalid HTTP status: #{expected_status.inspect}"
              end
          end
        end

        # @api private
        # Provides an implementation for `have_http_status` matching against
        # `ActionDispatch::TestResponse` http status category queries.
        #
        # Not intended to be instantiated directly.
        #
        # @example
        #   expect(response).to have_http_status(:success)
        #   expect(response).to have_http_status(:error)
        #   expect(response).to have_http_status(:missing)
        #   expect(response).to have_http_status(:redirect)
        #
        # @see RSpec::Rails::Matchers.have_http_status
        # @see ActionDispatch::TestResponse
        class GenericStatus < RSpec::Matchers::BuiltIn::BaseMatcher
          include HaveHttpStatus

          # @return [Array<Symbol>] of status codes which represent a HTTP status
          #   code "group"
          # @see https://github.com/rails/rails/blob/master/actionpack/lib/action_dispatch/testing/test_response.rb `ActionDispatch::TestResponse`
          def self.valid_statuses
            [
              :error, :success, :missing,
              :server_error, :successful, :not_found,
              :redirect
            ]
          end

          def initialize(type)
            unless self.class.valid_statuses.include?(type)
              raise ArgumentError, "Invalid generic HTTP status: #{type.inspect}"
            end
            @expected = type
            @actual = nil
            @invalid_response = nil
          end

          # @return [Boolean] `true` if Rack's associated numeric HTTP code matched
          #   the `response` code or the named response status
          def matches?(response)
            test_response = as_test_response(response)
            @actual = test_response.response_code
            check_expected_status(test_response, expected)
          rescue TypeError => _ignored
            @invalid_response = response
            false
          end

          # @return [String]
          def description
            "respond with #{type_message}"
          end

          # @return [String] explaining why the match failed
          def failure_message
            invalid_response_type_message ||
            "expected the response to have #{type_message} but it was #{actual}"
          end

          # @return [String] explaining why the match failed
          def failure_message_when_negated
            invalid_response_type_message ||
            "expected the response not to have #{type_message} but it was #{actual}"
          end

        protected

          if 5 < ::Rails::VERSION::MAJOR ||
             (::Rails::VERSION::MAJOR == 5 && 2 <= ::Rails::VERSION::MINOR)
            RESPONSE_METHODS = {
              :success => 'successful',
              :error => 'server_error',
              :missing => 'not_found'
            }.freeze
          else
            RESPONSE_METHODS = {
              :successful => 'success',
              :server_error => 'error',
              :not_found => 'missing'
            }.freeze
          end

          def check_expected_status(test_response, expected)
            test_response.send(
              "#{RESPONSE_METHODS.fetch(expected, expected)}?")
          end

        private

          # @return [String] formating the expected status and associated code(s)
          def type_message
            @type_message ||= (expected == :error ? "an error" : "a #{expected}") +
              " status code (#{type_codes})"
          end

          # @return [String] formatting the associated code(s) for the various
          #   status code "groups"
          # @see https://github.com/rails/rails/blob/master/actionpack/lib/action_dispatch/testing/test_response.rb `ActionDispatch::TestResponse`
          # @see https://github.com/rack/rack/blob/master/lib/rack/response.rb `Rack::Response`
          def type_codes
            # At the time of this commit the most recent version of
            # `ActionDispatch::TestResponse` defines the following aliases:
            #
            #     alias_method :success?,  :successful?
            #     alias_method :missing?,  :not_found?
            #     alias_method :redirect?, :redirection?
            #     alias_method :error?,    :server_error?
            #
            # It's parent `ActionDispatch::Response` includes
            # `Rack::Response::Helpers` which defines the aliased methods as:
            #
            #     def successful?;   status >= 200 && status < 300; end
            #     def redirection?;  status >= 300 && status < 400; end
            #     def server_error?; status >= 500 && status < 600; end
            #     def not_found?;    status == 404;                 end
            #
            # @see https://github.com/rails/rails/blob/ca200378/actionpack/lib/action_dispatch/testing/test_response.rb#L17-L27
            # @see https://github.com/rails/rails/blob/ca200378/actionpack/lib/action_dispatch/http/response.rb#L74
            # @see https://github.com/rack/rack/blob/ce4a3959/lib/rack/response.rb#L119-L122
            @type_codes ||= case expected
                            when :error, :server_error
                              "5xx"
                            when :success, :successful
                              "2xx"
                            when :missing, :not_found
                              "404"
                            when :redirect
                              "3xx"
                            end
          end
        end
      end

      # @api public
      # Passes if `response` has a matching HTTP status code.
      #
      # The following symbolic status codes are allowed:
      #
      # - `Rack::Utils::SYMBOL_TO_STATUS_CODE`
      # - One of the defined `ActionDispatch::TestResponse` aliases:
      #   - `:error`
      #   - `:missing`
      #   - `:redirect`
      #   - `:success`
      #
      # @example Accepts numeric and symbol statuses
      #   expect(response).to have_http_status(404)
      #   expect(response).to have_http_status(:created)
      #   expect(response).to have_http_status(:success)
      #   expect(response).to have_http_status(:error)
      #   expect(response).to have_http_status(:missing)
      #   expect(response).to have_http_status(:redirect)
      #
      # @example Works with standard `response` objects and Capybara's `page`
      #   expect(response).to have_http_status(404)
      #   expect(page).to     have_http_status(:created)
      #
      # @see https://github.com/rails/rails/blob/master/actionpack/lib/action_dispatch/testing/test_response.rb `ActionDispatch::TestResponse`
      # @see https://github.com/rack/rack/blob/master/lib/rack/utils.rb `Rack::Utils::SYMBOL_TO_STATUS_CODE`
      def have_http_status(target)
        raise ArgumentError, "Invalid HTTP status: nil" unless target
        HaveHttpStatus.matcher_for_status(target)
      end
    end
  end
end
