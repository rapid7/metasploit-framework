module RKelly
  module JS
    class Base
      attr_reader :properties, :return, :value
      def initialize
        @properties = Hash.new { |h,k|
          h[k] = Property.new(k, :undefined, self)
        }
        @return     = nil
        @returned   = false
        @value      = self
        self['Class'] = self.class.to_s.split('::').last
      end

      def [](name)
        return self.properties[name] if has_property?(name)
        if self.properties['prototype'].value != :undefined
          self.properties['prototype'].value[name]
        else
          RKelly::Runtime::UNDEFINED
        end
      end

      def []=(name, value)
        return unless can_put?(name)
        if has_property?(name)
          self.properties[name].value = value
        else
          self.properties[name] = Property.new(name, value, self)
        end
      end

      def can_put?(name)
        if !has_property?(name)
          return true if self.properties['prototype'].nil?
          return true if self.properties['prototype'].value.nil?
          return true if self.properties['prototype'].value == :undefined
          return self.properties['prototype'].value.can_put?(name)
        end
        !self.properties[name].read_only?
      end

      def has_property?(name)
        return true if self.properties.has_key?(name)
        return false if self.properties['prototype'].nil?
        return false if self.properties['prototype'].value.nil?
        return false if self.properties['prototype'].value == :undefined
        self.properties['prototype'].value.has_property?(name)
      end

      def delete(name)
        return true unless has_property?(name)
        return false if self.properties[name].dont_delete?
        self.properties.delete(name)
        true
      end

      def default_value(hint)
        case hint
        when 'Number'
          value_of = self['valueOf']
          if value_of.function || value_of.value.is_a?(RKelly::JS::Function)
            return value_of
          end
          to_string = self['toString']
          if to_string.function || to_string.value.is_a?(RKelly::JS::Function)
            return to_string
          end
        end
      end

      def return=(value)
        @returned = true
        @return = value
      end

      def returned?; @returned; end

      private
      def unbound_method(name, object_id = nil, &block)
        name = "#{name}_#{self.class.to_s.split('::').last}_#{object_id}"
        unless RKelly::JS::Base.instance_methods.include?(name.to_sym)
          RKelly::JS::Base.class_eval do
            define_method(name, &block)
          end
        end
        RKelly::JS::Base.instance_method(name)
      end
    end
  end
end
