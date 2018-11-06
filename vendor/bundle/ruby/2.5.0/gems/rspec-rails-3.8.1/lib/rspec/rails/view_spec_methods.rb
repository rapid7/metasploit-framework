module RSpec
  module Rails
    # Adds methods (generally to ActionView::TestCase::TestController).
    # Intended for use in view specs.
    module ViewSpecMethods
      module_function

      # Adds methods `extra_params=` and `extra_params` to the indicated class.
      # When class is `::ActionView::TestCase::TestController`, these methods
      # are exposed in view specs on the `controller` object.
      def add_to(klass)
        return if klass.method_defined?(:extra_params) && klass.method_defined?(:extra_params=)

        klass.module_exec do
          # Set any extra parameters that rendering a URL for this view
          # would require.
          #
          # @example
          #
          #     # In "spec/views/widgets/show.html.erb_spec.rb":
          #     before do
          #       widget = Widget.create!(:name => "slicer")
          #       controller.extra_params = { :id => widget.id }
          #     end
          def extra_params=(hash)
            @extra_params = hash
            request.path =
              ViewPathBuilder.new(::Rails.application.routes).path_for(
                extra_params.merge(request.path_parameters)
              )
          end

          # Use to read extra parameters that are set in the view spec.
          #
          # @example
          #
          #     # After the before in the above example:
          #     controller.extra_params
          #     # => { :id => 4 }
          def extra_params
            @extra_params ||= {}
            @extra_params.dup.freeze
          end
        end
      end

      # Removes methods `extra_params=` and `extra_params` from the indicated class.
      def remove_from(klass)
        klass.module_exec do
          undef extra_params= if klass.method_defined?(:extra_params=)
          undef extra_params  if klass.method_defined?(:extra_params)
        end
      end
    end
  end
end
