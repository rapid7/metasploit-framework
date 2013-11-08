module Metasploit
  module Framework
    # @example
    #   extend Metasploit::Framework::Synchronization
    #
    #   # Will synchronize :foo with MyNamespace::Synchronization::Foo
    #   # Will synchronize :bar with MyNamespace::Synchronization::Bar#
    #   synchronizes :foo,
    #                :bar,
    #                namespace_name: "MyNamespace"
    #
    module Synchronizes
      def synchronization_classes(options={}, &block)
        options.assert_valid_keys(:for)
        suffix = options.fetch(:for)

        synchronization_classes_by_suffix[suffix].each(&block)
      end

      def synchronization_classes_by_suffix
        @synchronized_classes_by_suffix ||= Hash.new { |hash, suffix|
          synchronized_attributes = synchronized_attributes_by_suffix.fetch(suffix)
          namespace_name = "Metasploit::Framework::#{suffix}::Synchronization"

          hash[suffix] = synchronized_attributes.collect { |attribute|
            synchronization_class_name = "#{namespace_name}::#{attribute.to_s.camelize}"

            synchronization_class_name.constantize
          }
        }
      end

      def synchronized_attributes_by_suffix
        @synchronized_attributes_by_suffix ||= {}
      end

      def synchronizes(*attributes_and_options)
        options = attributes_and_options.extract_options!
        attributes = attributes_and_options

        options.assert_valid_keys(:for)
        suffix = options.fetch(:for)

        synchronized_attributes_by_suffix[suffix] = attributes
      end
    end
  end
end