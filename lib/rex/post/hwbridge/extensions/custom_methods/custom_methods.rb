#
# -*- coding: binary -*-
require 'rex/post/hwbridge/client'

module Rex
module Post
module HWBridge
module Extensions
module CustomMethods

###
# Custom Methods extension - set of commands provided by the HW itself
###

class CustomMethods < Extension

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
  # Converts a cmd and args to a request to the hardware device
  # cmd is the cmd without a path
  # args are all KEY=value pairs.  All checks are assumed to have already been done
  # methods is a hash of all methods and their formatting
  # returns a formated response
  #
  def send_request(cmd, args, methods)
    arguments = ""
    if args.size > 0
      arguments = "?"
      first = true
      args.each do |arg|
        arguments += "&" if not first
        arguments += arg
        first = false
      end
    end
    resp = { "success" => false }
    methods.each do |meth|
      if meth["method_name"] =~ /#{cmd}$/
        resp = client.send_request("#{meth["method_name"]}#{arguments}")
        if resp.has_key? "value" and meth.has_key? "return"
          case meth["return"]
          when "nil"
            print_warning("A return was given when none was expected")
          when "int"
            resp["value"] = resp["value"].to_i
          when "hex"
            resp["value"] = "0x" + resp["value"].to_s(16)
          when "boolean"
            resp["value"] = resp["value"] == "true" ? true : false
          when "float"
            resp["value"] = resp["value"].to_f
          end
        end
      end
    end
    resp
  end

end

end
end
end
end
end
