module Nexpose
  # Base class for all API 2.0 objects which are derived from JSON
  # representations.
  #
  # This class is not intended to be used by customers, but to extend
  # functionality in the gem itself.
  #
  # To use this class, do the following:
  # * Subclass APIObject
  # * Do NOT provide a constructor method, or it must take no arguments.
  # * Clearly document all attributes which the customer can expect to see.
  # * Clearly document those attributes which are lazily loaded.
  # * If applicable, implement a load method which calls new.object_from_hash
  #
  class APIObject
    # Populate object methods and attributes from a JSON-derived hash.
    #
    # @param [Nexpose::Connection] nsc Active connection to a console.
    # @param [Hash] hash Result of running JSON#parse with the
    #   symbolize_names parameter to a 2.0 API response.
    #   Pass hash[:resources] if the response is pageable.
    #
    def object_from_hash(nsc, hash)
      hash.each do |k, v|
        next if k == :url # Do not store self-referential URL.
        # Store resource URLs separately and create lazy accessors.
        if v.is_a?(Hash) && v.key?(:url)
          self.class.send(:define_method, k, proc { |conn = nsc| load_resource(conn, k, v[:url].gsub(/.*\/api/, '/api')) })
        else
          # Convert timestamps.
          if v.is_a?(String) && v.match(/^\d{8}T\d{6}\.\d{3}/)
            instance_variable_set("@#{k}", ISO8601.to_time(v))
          elsif v.is_a?(Array) && k == :attributes
            instance_variable_set("@#{k}", v.map { |h| { h[:key] => h[:value] } })
          else
            instance_variable_set("@#{k}", v)
          end
          self.class.send(:define_method, k, proc { instance_variable_get("@#{k}") })
        end
      end
      self
    end

    private

    # Load a resource from the security console. Once loaded, the value is
    # cached so that it need not be loaded again.
    #
    # @param [Connection] nsc Active connection to the console.
    # @param [Symbol] k Original key name, used to identify the class to load.
    # @param [String] url Truncated URL to use to retrieve the resource.
    # @return [Array[?]] Collection of "k" marshalled object.
    #
    def load_resource(nsc, k, url)
      obj  = class_from_string(k)
      resp = AJAX.get(nsc, url, AJAX::CONTENT_TYPE::JSON)
      hash = JSON.parse(resp, symbolize_names: true)
      if hash.is_a?(Array)
        resources = hash.map { |e| obj.method(:new).call.object_from_hash(nsc, e) }
      elsif hash.key?(:resources)
        resources = hash[:resources].map { |e| obj.method(:new).call.object_from_hash(nsc, e) }
      else
        resources = obj.method(:new).call.object_from_hash(nsc, hash)
      end
      instance_variable_set("@#{k}", resources)
      self.class.send(:define_method, k, proc { instance_variable_get("@#{k}") })
      resources
    end

    # Get the class referred to by a field name.
    #
    # For example, this method will translate a field name like "malware_kits"
    # into to corresponding MalwareKit class.
    #
    # @param [String] field Snake-case name of a field.
    # @return [Class] Class associated with the provided field.
    #
    def class_from_string(field)
      str = field.to_s.split('_').map(&:capitalize!).join
      str = 'Vulnerability' if str == 'Vulnerabilities'
      str.chop! if str.end_with?('s')
      Object.const_get('Nexpose').const_get(str)
    end
  end

  module TypedAccessor
    def typed_accessor(name, type)
      # here we dynamically define accessor methods
      define_method(name) do
        instance_variable_get("@#{name}")
      end

      define_method("#{name}=") do |value|
        instance_variable_set("@#{name}", value)
      end

      define_method("#{name}_type") do
        type
      end
    end
  end

end
