module Formtastic
  # Required for formtastic.css to be discoverable in the asset pipeline
  # @private
  class Engine < ::Rails::Engine
    initializer 'formtastic.initialize' do
      ActiveSupport.on_load(:action_view) do
        include Formtastic::Helpers::FormHelper
      end
    end
  end
end