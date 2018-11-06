module RSpec
  module Rails
    # Helpers for making instance variables available to views.
    module ViewAssigns
      # Assigns a value to an instance variable in the scope of the
      # view being rendered.
      #
      # @example
      #
      #     assign(:widget, stub_model(Widget))
      def assign(key, value)
        _encapsulated_assigns[key] = value
      end

      # Compat-shim for AbstractController::Rendering#view_assigns
      #
      # _assigns was deprecated in favor of view_assigns after
      # Rails-3.0.0 was released. Since we are not able to predict when
      # the _assigns/view_assigns patch will be released (I thought it
      # would have been in 3.0.1, but 3.0.1 bypassed this change for a
      # security fix), this bit ensures that we do the right thing without
      # knowing anything about the Rails version we are dealing with.
      #
      # Once that change _is_ released, this can be changed to something
      # that checks for the Rails version when the module is being
      # interpreted, as it was before commit dd0095.
      def view_assigns
        super.merge(_encapsulated_assigns)
      rescue
        _assigns
      end

      # @private
      def _assigns
        super.merge(_encapsulated_assigns)
      end

    private

      def _encapsulated_assigns
        @_encapsulated_assigns ||= {}
      end
    end
  end
end
