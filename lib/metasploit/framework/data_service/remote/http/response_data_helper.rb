require 'ostruct'

#
# HTTP response helper class
#
module ResponseDataHelper

  #
  # Converts an HTTP response to an OpenStruct object
  #
  def json_to_open_struct_object(response_wrapper, returns_on_error = nil)
    if (response_wrapper.expected)
      begin
        body = response_wrapper.response.body
        if (not body.nil? and not body.empty?)
          return JSON.parse(body, object_class: OpenStruct)
        end
      rescue Exception => e
        puts "open struct conversion failed #{e.message}"
      end
    end

    return returns_on_error
  end

  #
  # Converts a hash to an open struct
  #
  def open_struct(hash)
    OpenStruct.new(hash)
  end

end