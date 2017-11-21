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

  # Processes a Base64 encoded file included in a JSON request.
  # Saves the file in the location specified in the parameter.
  #
  # @param base64_file [String] The Base64 encoded file.
  # @param save_dir [String] The location to store the file. This should include the file's name.
  # @return [String] The location where the file was successfully stored.
  def process_file(base64_file, save_dir)
    decoded_file = Base64.urlsafe_decode64(base64_file)
    begin
      # If we are running the data service on the same box this will ensure we only write
      # the file if it is somehow not there already.
      unless File.exists?(save_dir) && File.read(save_dir) == decoded_file
        File.open(save_dir, 'w+') { |file| file.write(decoded_file) }
      end
    rescue Exception => e
      puts "There was an error writing the file: #{e}"
      e.backtrace.each { |line| puts "#{line}\n"}
    end
    save_dir
  end

  #
  # Converts a hash to an open struct
  #
  def open_struct(hash)
    OpenStruct.new(hash)
  end

end