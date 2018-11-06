require 'factory_bot/attribute/static'
require 'factory_bot/attribute/dynamic'
require 'factory_bot/attribute/association'
require 'factory_bot/attribute/sequence'

module FactoryBot
  # @api private
  class Attribute
    attr_reader :name, :ignored

    def initialize(name, ignored)
      @name = name.to_sym
      @ignored = ignored
      ensure_non_attribute_writer!
    end

    def to_proc
      -> { }
    end

    def association?
      false
    end

    def alias_for?(attr)
      FactoryBot.aliases_for(attr).include?(name)
    end

    private

    def ensure_non_attribute_writer!
      NonAttributeWriterValidator.new(@name).validate!
    end

    class NonAttributeWriterValidator
      def initialize(method_name)
        @method_name = method_name.to_s
        @method_name_setter_match = @method_name.match(/(.*)=$/)
      end

      def validate!
        if method_is_writer?
          raise AttributeDefinitionError, error_message
        end
      end

      private

      def method_is_writer?
        !!@method_name_setter_match
      end

      def attribute_name
        @method_name_setter_match[1]
      end

      def error_message
        "factory_bot uses '#{attribute_name} value' syntax rather than '#{attribute_name} = value'"
      end
    end
  end
end
