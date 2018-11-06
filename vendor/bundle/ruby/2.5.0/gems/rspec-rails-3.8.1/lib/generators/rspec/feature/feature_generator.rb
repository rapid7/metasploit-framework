require 'generators/rspec'

module Rspec
  module Generators
    # @private
    class FeatureGenerator < Base
      class_option :feature_specs, :type => :boolean, :default => true,  :desc => "Generate feature specs"
      class_option :singularize,   :type => :boolean, :default => false, :desc => "Singularize the generated feature"

      def generate_feature_spec
        return unless options[:feature_specs]

        template template_name, File.join('spec/features', class_path, filename)
      end

      def template_name
        options[:singularize] ? 'feature_singular_spec.rb' : 'feature_spec.rb'
      end

      def filename
        if options[:singularize]
          "#{file_name.singularize}_spec.rb"
        else
          "#{file_name}_spec.rb"
        end
      end
    end
  end
end
