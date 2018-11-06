RSpec::Support.require_rspec_support 'matcher_definition'

module RSpec
  module Support
    # Provide additional output details beyond what `inspect` provides when
    # printing Time, DateTime, or BigDecimal
    # @api private
    class ObjectFormatter # rubocop:disable Metrics/ClassLength
      ELLIPSIS = "..."

      attr_accessor :max_formatted_output_length

      # Methods are deferred to a default instance of the class to maintain the interface
      # For example, calling ObjectFormatter.format is still possible
      def self.default_instance
        @default_instance ||= new
      end

      def self.format(object)
        default_instance.format(object)
      end

      def self.prepare_for_inspection(object)
        default_instance.prepare_for_inspection(object)
      end

      def initialize(max_formatted_output_length=200)
        @max_formatted_output_length = max_formatted_output_length
        @current_structure_stack = []
      end

      def format(object)
        if max_formatted_output_length.nil?
          prepare_for_inspection(object).inspect
        else
          formatted_object = prepare_for_inspection(object).inspect
          if formatted_object.length < max_formatted_output_length
            formatted_object
          else
            beginning = truncate_string formatted_object, 0, max_formatted_output_length / 2
            ending = truncate_string formatted_object, -max_formatted_output_length / 2, -1
            beginning + ELLIPSIS + ending
          end
        end
      end

      # Prepares the provided object to be formatted by wrapping it as needed
      # in something that, when `inspect` is called on it, will produce the
      # desired output.
      #
      # This allows us to apply the desired formatting to hash/array data structures
      # at any level of nesting, simply by walking that structure and replacing items
      # with custom items that have `inspect` defined to return the desired output
      # for that item. Then we can just use `Array#inspect` or `Hash#inspect` to
      # format the entire thing.
      def prepare_for_inspection(object)
        case object
        when Array
          prepare_array(object)
        when Hash
          prepare_hash(object)
        else
          inspector_class = INSPECTOR_CLASSES.find { |inspector| inspector.can_inspect?(object) }
          inspector_class.new(object, self)
        end
      end

      def prepare_array(array)
        with_entering_structure(array) do
          array.map { |element| prepare_element(element) }
        end
      end

      def prepare_hash(input_hash)
        with_entering_structure(input_hash) do
          sort_hash_keys(input_hash).inject({}) do |output_hash, key_and_value|
            key, value = key_and_value.map { |element| prepare_element(element) }
            output_hash[key] = value
            output_hash
          end
        end
      end

      def sort_hash_keys(input_hash)
        if input_hash.keys.all? { |k| k.is_a?(String) || k.is_a?(Symbol) }
          Hash[input_hash.sort_by { |k, _v| k.to_s }]
        else
          input_hash
        end
      end

      def prepare_element(element)
        if recursive_structure?(element)
          case element
          when Array then InspectableItem.new('[...]')
          when Hash then InspectableItem.new('{...}')
          else raise # This won't happen
          end
        else
          prepare_for_inspection(element)
        end
      end

      def with_entering_structure(structure)
        @current_structure_stack.push(structure)
        return_value = yield
        @current_structure_stack.pop
        return_value
      end

      def recursive_structure?(object)
        @current_structure_stack.any? { |seen_structure| seen_structure.equal?(object) }
      end

      InspectableItem = Struct.new(:text) do
        def inspect
          text
        end

        def pretty_print(pp)
          pp.text(text)
        end
      end

      BaseInspector = Struct.new(:object, :formatter) do
        def self.can_inspect?(_object)
          raise NotImplementedError
        end

        def inspect
          raise NotImplementedError
        end

        def pretty_print(pp)
          pp.text(inspect)
        end
      end

      class TimeInspector < BaseInspector
        FORMAT = "%Y-%m-%d %H:%M:%S"

        def self.can_inspect?(object)
          Time === object
        end

        if Time.method_defined?(:nsec)
          def inspect
            object.strftime("#{FORMAT}.#{"%09d" % object.nsec} %z")
          end
        else # for 1.8.7
          def inspect
            object.strftime("#{FORMAT}.#{"%06d" % object.usec} %z")
          end
        end
      end

      class DateTimeInspector < BaseInspector
        FORMAT = "%a, %d %b %Y %H:%M:%S.%N %z"

        def self.can_inspect?(object)
          defined?(DateTime) && DateTime === object
        end

        # ActiveSupport sometimes overrides inspect. If `ActiveSupport` is
        # defined use a custom format string that includes more time precision.
        def inspect
          if defined?(ActiveSupport)
            object.strftime(FORMAT)
          else
            object.inspect
          end
        end
      end

      class BigDecimalInspector < BaseInspector
        def self.can_inspect?(object)
          defined?(BigDecimal) && BigDecimal === object
        end

        def inspect
          "#{object.to_s('F')} (#{object.inspect})"
        end
      end

      class DescribableMatcherInspector < BaseInspector
        def self.can_inspect?(object)
          Support.is_a_matcher?(object) && object.respond_to?(:description)
        end

        def inspect
          object.description
        end
      end

      class UninspectableObjectInspector < BaseInspector
        OBJECT_ID_FORMAT = '%#016x'

        def self.can_inspect?(object)
          object.inspect
          false
        rescue NoMethodError
          true
        end

        def inspect
          "#<#{klass}:#{native_object_id}>"
        end

        def klass
          Support.class_of(object)
        end

        # http://stackoverflow.com/a/2818916
        def native_object_id
          OBJECT_ID_FORMAT % (object.__id__ << 1)
        rescue NoMethodError
          # In Ruby 1.9.2, BasicObject responds to none of #__id__, #object_id, #id...
          '-'
        end
      end

      class DelegatorInspector < BaseInspector
        def self.can_inspect?(object)
          defined?(Delegator) && Delegator === object
        end

        def inspect
          "#<#{object.class}(#{formatter.format(object.__getobj__)})>"
        end
      end

      class InspectableObjectInspector < BaseInspector
        def self.can_inspect?(object)
          object.inspect
          true
        rescue NoMethodError
          false
        end

        def inspect
          object.inspect
        end
      end

      INSPECTOR_CLASSES = [
        TimeInspector,
        DateTimeInspector,
        BigDecimalInspector,
        UninspectableObjectInspector,
        DescribableMatcherInspector,
        DelegatorInspector,
        InspectableObjectInspector
      ].tap do |classes|
        # 2.4 has improved BigDecimal formatting so we do not need
        # to provide our own.
        # https://github.com/ruby/bigdecimal/pull/42
        classes.delete(BigDecimalInspector) if RUBY_VERSION >= '2.4'
      end

    private

      # Returns the substring defined by the start_index and end_index
      # If the string ends with a partial ANSI code code then that
      # will be removed as printing partial ANSI
      # codes to the terminal can lead to corruption
      def truncate_string(str, start_index, end_index)
        cut_str = str[start_index..end_index]

        # ANSI color codes are like: \e[33m so anything with \e[ and a
        # number without a 'm' is an incomplete color code
        cut_str.sub(/\e\[\d+$/, '')
      end
    end
  end
end
