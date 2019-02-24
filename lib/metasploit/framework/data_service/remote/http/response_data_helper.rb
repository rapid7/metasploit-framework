require 'digest'

#
# HTTP response helper class
#
module ResponseDataHelper


  def process_response(response_wrapper)
    begin
      if response_wrapper.expected
        response_wrapper.response.body
      end
    rescue => e
      elog "Error processing response: #{e.message}"
      e.backtrace.each { |line| elog line }
    end
  end

  #
  # Converts an HTTP response to a Hash
  #
  # @param [ResponseWrapper] A wrapped HTTP response containing a JSON body.
  # @return [Hash] A Hash interpretation of the JSON body.
  #
  def json_to_hash(response_wrapper)
    begin
      body = process_response(response_wrapper)
      if !body.nil? && !body.empty?
        parsed_body = JSON.parse(body, symbolize_names: true)
        return parsed_body[:data]
      end
    rescue => e
      elog "Error parsing response as JSON: #{e.message}"
      e.backtrace.each { |line| elog line }
    end
  end

  #
  # Converts an HTTP response to an Mdm Object
  #
  # @param [ResponseWrapper] A wrapped HTTP response containing a JSON body.
  # @param [String] The Mdm class to convert the JSON to.
  # @param [Anything] A failsafe response to return if no objects are found.
  # @return [ActiveRecord::Base] An object of type mdm_class, which inherits from ActiveRecord::Base
  #
  def json_to_mdm_object(response_wrapper, mdm_class, returns_on_error = nil)
    if response_wrapper.expected
      begin
        body = process_response(response_wrapper)
        if !body.nil? && !body.empty?
          parsed_body = JSON.parse(body, symbolize_names: true)
          data = Array.wrap(parsed_body[:data])
          rv = []
          data.each do |json_object|
            rv << to_ar(mdm_class.constantize, json_object)
          end
          return rv
        end
      rescue => e
        elog "Mdm Object conversion failed #{e.message}"
        e.backtrace.each { |line| elog "#{line}" }
      end
    end

    return returns_on_error
  end

  # Processes a Base64 encoded file included in a JSON request.
  # Saves the file in the location specified in the parameter.
  #
  # @param base64_file [String] The Base64 encoded file.
  # @param save_path [String] The location to store the file. This should include the file's name.
  # @return [String] The location where the file was successfully stored.
  def process_file(base64_file, save_path)
    decoded_file = Base64.urlsafe_decode64(base64_file)
    begin
      # If we are running the data service on the same box this will ensure we only write
      # the file if it is somehow not there already.
      unless File.exists?(save_path) && File.read(save_path) == decoded_file
        File.open(save_path, 'w+') { |file| file.write(decoded_file) }
      end
    rescue => e
      elog "There was an error writing the file: #{e}"
      e.backtrace.each { |line| elog "#{line}\n"}
    end
    save_path
  end

  # Converts a Hash or JSON string to an ActiveRecord object.
  # Importantly, this retains associated objects if they are in the JSON string.
  #
  # Modified from https://github.com/swdyh/toar/
  # Credit to https://github.com/swdyh
  #
  # @param [String] klass The ActiveRecord class to convert the JSON/Hash to.
  # @param [String] val The JSON string, or Hash, to convert.
  # @param [Class] base_class The base class to build back to. Used for recursion.
  # @return [ActiveRecord::Base] A klass object, which inherits from ActiveRecord::Base.
  def to_ar(klass, val, base_object = nil)
    return nil unless val
    data = val.class == Hash ? val.dup : JSON.parse(val, symbolize_names: true)
    obj = base_object || klass.new

    obj_associations = klass.reflect_on_all_associations(:has_many).reduce({}) do |reflection, i|
      reflection[i.options[:through]] = i if i.options[:through]
      reflection
    end

    obj_attribute_names = obj.attributes.transform_keys(&:to_sym).keys

    data.except(*obj_attribute_names).each do |k, v|
      association = klass.reflect_on_association(k)
      next unless association

      case association.macro
        when :belongs_to
          data.delete("#{k}_id")
          # Polymorphic associations do not auto-create the 'build_model' method
          next if association.options[:polymorphic]
          to_ar(association.klass, v, obj.send("build_#{k}"))
          obj.class_eval do
            define_method("#{k}_id") { obj.send(k).id }
          end
        when :has_one
          to_ar(association.klass, v, obj.send("build_#{k}"))
        when :has_many
          obj.send(k).proxy_association.target =
              v.map { |i| to_ar(association.klass, i) }

          as_th = obj_associations[k.to_sym]
          if as_th
            obj.send(as_th.name).proxy_association.target =
                v.map { |i| to_ar(as_th.klass, i[as_th.source_reflection_name.to_s]) }
          end
      end
    end
    obj.assign_attributes(data.slice(*obj_attribute_names))

    obj.instance_eval do
      # prevent save
      def valid?(_context = nil)
        false
      end
    end
    obj
  end

end
