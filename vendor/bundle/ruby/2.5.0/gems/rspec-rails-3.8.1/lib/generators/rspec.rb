require 'rails/generators/named_base'
require 'rspec/rails/feature_check'

# @private
# Weirdly named generators namespace (should be `RSpec`) for compatability with
# rails loading.
module Rspec
  # @private
  module Generators
    # @private
    class Base < ::Rails::Generators::NamedBase
      include RSpec::Rails::FeatureCheck

      def self.source_root(path = nil)
        if path
          @_rspec_source_root = path
        else
          @_rspec_source_root ||= File.expand_path(File.join(File.dirname(__FILE__), 'rspec', generator_name, 'templates'))
        end
      end

      if ::Rails::VERSION::STRING < '3.1'
        def module_namespacing
          yield if block_given?
        end
      end
    end
  end
end

# @private
module Rails
  module Generators
    # @private
    class GeneratedAttribute
      def input_type
        @input_type ||= if type == :text
                          "textarea"
                        else
                          "input"
                        end
      end
    end
  end
end
