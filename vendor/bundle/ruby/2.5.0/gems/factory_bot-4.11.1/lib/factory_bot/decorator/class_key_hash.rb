module FactoryBot
  class Decorator
    class ClassKeyHash < Decorator
      def [](key)
        @component[symbolized_key key]
      end

      def []=(key, value)
        @component[symbolized_key key] = value
      end

      def key?(key)
        @component.key? symbolized_key(key)
      end

      private

      def symbolized_key(key)
        if key.respond_to?(:to_sym)
          key.to_sym
        elsif FactoryBot.allow_class_lookup
          ActiveSupport::Deprecation.warn "Looking up factories by class is deprecated and will be removed in 5.0. Use symbols instead and set FactoryBot.allow_class_lookup = false", caller
          key.to_s.underscore.to_sym
        end
      end
    end
  end
end
