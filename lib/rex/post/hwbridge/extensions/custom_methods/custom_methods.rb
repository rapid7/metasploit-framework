#
# -*- coding: binary -*-
require 'rex/post/hwbridge/client'
require 'uri'

module Rex
module Post
module HWBridge
module Extensions
module CustomMethods

###
# Custom Methods extension - set of commands provided by the HW itself
###

class CustomMethods < Extension

  # @param path [String] The route advertised by the bridge
  # @return [String, nil] The console command, or nil if the route is unsafe
  def self.command_name(path)
    return unless path.is_a?(String) && path.ascii_only?

    return unless path.match?(%r{\A/?(?:[a-zA-Z0-9_~.-]+/)*[a-zA-Z_][a-zA-Z0-9_]*\z})

    # Dot segments can escape the configured bridge path.
    segments = path.split('/')
    return if segments.any? { |segment| segment == '.' || segment == '..' }

    segments.last
  end

  def initialize(client)
    super(client, 'automotive')

    # Alias the following things on the client object so that they
    # can be directly referenced
    client.register_extension_aliases(
      [
        {
          'name' => 'custom_methods',
          'ext'  => self
        }
      ])
  end

  #
  # Converts a command and its arguments to a request to the hardware device.
  #
  # @param cmd [String] The command without a path
  # @param args [Array<String>] The KEY=value arguments
  # @param methods [Array<Hash>] The advertised method definitions
  # @return [Hash] The hardware response, or a failure if the route or reply is invalid
  #
  def send_request(cmd, args, methods)
    return { 'success' => false } unless cmd.is_a?(String) && methods.is_a?(Array)

    matches = methods.count { |meth| meth.is_a?(Hash) && self.class.command_name(meth['method_name']) == cmd }
    return { 'success' => false } if matches.zero?
    return { 'success' => false, 'status' => 'Ambiguous custom method name' } if matches > 1

    arguments = ""
    if args.size > 0
      arguments = "?"
      first = true
      args.each do |arg|
        arguments += "&" if not first
        arguments += URI.encode_www_form([arg.split('=', 2)])
        first = false
      end
    end
    resp = { "success" => false }
    methods.each do |meth|
      if meth.is_a?(Hash) && self.class.command_name(meth['method_name']) == cmd
        resp = client.send_request("#{meth["method_name"]}#{arguments}")

        # The reply is whatever the hardware sent back: it can be missing
        # (nil) or valid JSON that is not an object.
        unless resp.is_a?(Hash)
          resp = { "success" => false, "status" => "Unexpected or missing reply from the hardware bridge" }
          next
        end

        if resp.has_key? "value" and meth.has_key? "return"
          case meth["return"]
          when "nil"
            print_warning("A return was given when none was expected")
          else
            resp["value"] = convert_value(meth["return"], resp["value"])
          end
        end
      end
    end
    resp
  end

protected

  #
  # Converts a value returned by the hardware to the type the method declared.
  # A value that cannot be converted to that type is returned unchanged.
  #
  # @param type [String] The declared return type: int, hex, boolean or float
  # @param value [Object] The value from the hardware reply
  # @return [Object] The converted value, or the original value
  #
  def convert_value(type, value)
    case type
    when "int"
      value.respond_to?(:to_i) ? value.to_i : value
    when "hex"
      value.is_a?(Integer) ? "0x" + value.to_s(16) : value
    when "boolean"
      value == "true"
    when "float"
      value.respond_to?(:to_f) ? value.to_f : value
    else
      value
    end
  end

end

end
end
end
end
end
