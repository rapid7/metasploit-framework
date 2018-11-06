require 'generators/factory_bot'
require 'factory_bot_rails'

module FactoryBot
  module Generators
    class ModelGenerator < Base
      argument(
        :attributes,
        type: :array,
        default: [],
        banner: "field:type field:type"
      )

      class_option(
        :dir,
        type: :string,
        default: "test/factories",
        desc: "The directory or file root where factories belong"
      )

      class_option(
        :suffix,
        type: :string,
        default: nil,
        desc: "Suffix to add factory file"
      )

      def create_fixture_file
        if File.exist?(factories_file)
          insert_factory_into_existing_file
        else
          create_factory_file
        end
      end

      private

      def factories_file
        options[:dir] + ".rb"
      end

      def insert_factory_into_existing_file
        insert_into_file(
          factories_file,
          factory_definition,
          after: "FactoryBot.define do\n"
        )
      end

      def create_factory_file
        file = File.join(options[:dir], "#{filename}.rb")
        create_file(file, single_file_factory_definition)
      end

      def factory_definition
<<-RUBY
  factory :#{singular_table_name}#{explicit_class_option} do
#{factory_attributes.gsub(/^/, "    ")}
  end
RUBY
      end

      def single_file_factory_definition
<<-RUBY
FactoryBot.define do
#{factory_definition.chomp}
end
RUBY
      end

      def factory_attributes
        attributes.map do |attribute|
          "#{attribute.name} { #{attribute.default.inspect} }"
        end.join("\n")
      end

      def filename
        if factory_bot_options[:filename_proc].present?
          factory_bot_options[:filename_proc].call(table_name)
        else
          [table_name, filename_suffix].compact.join('_')
        end
      end

      def filename_suffix
        factory_bot_options[:suffix] || options[:suffix]
      end

      def factory_bot_options
        generators.options[:factory_bot] || {}
      end

      def generators
        config = FactoryBot::Railtie.config
        config.respond_to?(:app_generators) ? config.app_generators : config.generators
      end
    end
  end
end
