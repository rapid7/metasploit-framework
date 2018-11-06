require 'generators/rspec'

module Rspec
  module Generators
    # @private
    class ObserverGenerator < Base
      def generate_observer_spec
        template 'observer_spec.rb',
                 File.join('spec', 'models', class_path, "#{file_name}_observer_spec.rb")
      end
    end
  end
end
