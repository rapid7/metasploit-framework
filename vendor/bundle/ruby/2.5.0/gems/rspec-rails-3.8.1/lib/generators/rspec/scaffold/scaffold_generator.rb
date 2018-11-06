require 'generators/rspec'
require 'rails/generators/resource_helpers'

module Rspec
  module Generators
    # @private
    class ScaffoldGenerator < Base
      include ::Rails::Generators::ResourceHelpers
      source_paths << File.expand_path("../../helper/templates", __FILE__)
      argument :attributes, :type => :array, :default => [], :banner => "field:type field:type"

      class_option :orm, :desc => "ORM used to generate the controller"
      class_option :template_engine, :desc => "Template engine to generate view files"
      class_option :singleton, :type => :boolean, :desc => "Supply to create a singleton controller"
      class_option :api, :type => :boolean, :desc => "Skip specs unnecessary for API-only apps"

      class_option :controller_specs, :type => :boolean, :default => true,  :desc => "Generate controller specs"
      class_option :view_specs,       :type => :boolean, :default => true,  :desc => "Generate view specs"
      class_option :helper_specs,     :type => :boolean, :default => true,  :desc => "Generate helper specs"
      class_option :routing_specs,    :type => :boolean, :default => true,  :desc => "Generate routing specs"

      def initialize(*args, &blk)
        @generator_args = args.first
        super(*args, &blk)
      end

      def generate_controller_spec
        return unless options[:controller_specs]

        template_file = File.join(
          'spec/controllers',
          controller_class_path,
          "#{controller_file_name}_controller_spec.rb"
        )
        if options[:api]
          template 'api_controller_spec.rb', template_file
        else
          template 'controller_spec.rb', template_file
        end
      end

      def generate_view_specs
        return if options[:api]
        return unless options[:view_specs] && options[:template_engine]

        copy_view :edit
        copy_view :index unless options[:singleton]
        copy_view :new
        copy_view :show
      end

      def generate_routing_spec
        return unless options[:routing_specs]

        template_file = File.join(
          'spec/routing',
          controller_class_path,
          "#{controller_file_name}_routing_spec.rb"
        )
        template 'routing_spec.rb', template_file
      end

      hook_for :integration_tool, :as => :integration

    protected

      attr_reader :generator_args

      def copy_view(view)
        template "#{view}_spec.rb",
                 File.join("spec/views", controller_file_path, "#{view}.html.#{options[:template_engine]}_spec.rb")
      end

      # support for namespaced-resources
      def ns_file_name
        return file_name if ns_parts.empty?
        "#{ns_prefix.map(&:underscore).join('/')}_#{ns_suffix.singularize.underscore}"
      end

      # support for namespaced-resources
      def ns_table_name
        return table_name if ns_parts.empty?
        "#{ns_prefix.map(&:underscore).join('/')}/#{ns_suffix.tableize}"
      end

      def ns_parts
        @ns_parts ||= begin
                        parts = generator_args[0].split(/\/|::/)
                        parts.size > 1 ? parts : []
                      end
      end

      def ns_prefix
        @ns_prefix ||= ns_parts[0..-2]
      end

      def ns_suffix
        @ns_suffix ||= ns_parts[-1]
      end

      def value_for(attribute)
        raw_value_for(attribute).inspect
      end

      def raw_value_for(attribute)
        case attribute.type
        when :string
          attribute.name.titleize
        when :integer, :float
          @attribute_id_map ||= {}
          @attribute_id_map[attribute] ||= @attribute_id_map.keys.size.next + attribute.default
        else
          attribute.default
        end
      end

      def banner
        self.class.banner
      end
    end
  end
end
