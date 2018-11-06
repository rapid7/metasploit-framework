module RSpec
  module Rails
    module Matchers
      # @api private
      #
      # Matcher class for `be_a_new`. Should not be instantiated directly.
      #
      # @see RSpec::Rails::Matchers#be_a_new
      class BeANew < RSpec::Matchers::BuiltIn::BaseMatcher
        # @private
        def initialize(expected)
          @expected = expected
        end

        # @private
        def matches?(actual)
          @actual = actual
          actual.is_a?(expected) && actual.new_record? && attributes_match?(actual)
        end

        # @api public
        # @see RSpec::Rails::Matchers#be_a_new
        def with(expected_attributes)
          attributes.merge!(expected_attributes)
          self
        end

        # @private
        def failure_message
          [].tap do |message|
            unless actual.is_a?(expected) && actual.new_record?
              message << "expected #{actual.inspect} to be a new #{expected.inspect}"
            end
            unless attributes_match?(actual)
              describe_unmatched_attributes = surface_descriptions_in(unmatched_attributes)
              if unmatched_attributes.size > 1
                message << "attributes #{describe_unmatched_attributes.inspect} were not set on #{actual.inspect}"
              else
                message << "attribute #{describe_unmatched_attributes.inspect} was not set on #{actual.inspect}"
              end
            end
          end.join(' and ')
        end

      private

        def attributes
          @attributes ||= {}
        end

        def attributes_match?(actual)
          attributes.stringify_keys.all? do |key, value|
            values_match?(value, actual.attributes[key])
          end
        end

        def unmatched_attributes
          attributes.stringify_keys.reject do |key, value|
            values_match?(value, actual.attributes[key])
          end
        end
      end

      # @api public
      # Passes if actual is an instance of `model_class` and returns `true` for
      # `new_record?`. Typically used to specify instance variables assigned to
      # views by controller actions
      #
      # Use the `with` method to specify the specific attributes to match on the
      # new record.
      #
      # @example
      #     get :new
      #     assigns(:thing).should be_a_new(Thing)
      #
      #     post :create, :thing => { :name => "Illegal Value" }
      #     assigns(:thing).should be_a_new(Thing).with(:name => nil)
      def be_a_new(model_class)
        BeANew.new(model_class)
      end
    end
  end
end
