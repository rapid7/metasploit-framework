module Nexpose
  module JsonSerializer
    @@namespace = 'Nexpose'

    def deserialize(data)
      data.each do |key, value|
        if respond_to?(key)
          property = value
          if value.respond_to? :each
            obj = resolve_type(key)
            unless obj.nil?
              if value.is_a?(Array)
                property = value.map { |dv| ((dv.respond_to? :each) ? create_object(obj, dv).deserialize(dv) : dv) }
              else
                property = create_object(obj, value).deserialize(value)
              end
            end
          elsif value.is_a?(String) && value.match(/^\d{8}T\d{6}\.\d{3}/)
            property = ISO8601.to_time(value)
          end
          instance_variable_set("@#{key}", property)
        end
      end
      self
    end

    def serialize
      hash = to_hash(Hash.new)
      JSON.generate(hash) unless hash.nil?
    end

    def to_hash(hash)
      self.instance_variables.each do |m|
        value = self.instance_variable_get(m)
        hash[m.to_s.delete('@')] = do_hash(value)
      end
      hash
    end

    private

    def do_hash(obj)
      if obj.is_a?(Array)
        obj = obj.map do |el|
          do_hash(el)
        end
      elsif obj.class.included_modules.include? JsonSerializer
        obj = obj.to_hash(Hash.new)
      end
      obj
    end

    def create_object(obj, data)
      if obj.respond_to?(:json_initializer)
        obj.method(:json_initializer).call(data)
      else
        obj.method(:new).call
      end
    end

    def resolve_type(field)
      class_name = normalize_field(field)
      type_attribute = "#{field}_type"

      if self.respond_to?(type_attribute)
        clazz = self.public_send(type_attribute)
      elsif Object.const_get(@@namespace).const_defined?(class_name)
        resolved = Object.const_get(@@namespace).const_get(class_name)
        clazz = resolved if resolved.included_modules.include? JsonSerializer
      end

      clazz
    end

    def normalize_field(field)
      class_name = field.to_s.split('_').map(&:capitalize!).join
      class_name = 'Vulnerability' if class_name == 'Vulnerabilities'
      class_name.chop! if class_name.end_with?('s')
      class_name
    end
  end
end
