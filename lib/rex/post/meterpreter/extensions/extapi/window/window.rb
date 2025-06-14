# -*- coding: binary -*-

module Rex
module Post
module Meterpreter
module Extensions
module Extapi
module Window

###
#
# This meterpreter extension contains extended API functions for
# querying and managing desktop windows.
#
###
class Window

  def initialize(client)
    @client = client
  end

  # Enumerate all the windows on the target.
  # If the specified parent window is nil, then all top-level windows
  # are enumerated. Otherwise, all child windows of the specified
  # parent window are enumerated.
  def enumerate(include_unknown = false, parent_window = nil)
    request = Packet.create_request(COMMAND_ID_EXTAPI_WINDOW_ENUM)

    if include_unknown
      request.add_tlv(TLV_TYPE_EXT_WINDOW_ENUM_INCLUDEUNKNOWN, true)
    end

    if !parent_window.nil?
      request.add_tlv(TLV_TYPE_EXT_WINDOW_ENUM_HANDLE, parent_window)
    end

    response = client.send_request(request)

    windows = []

    response.each(TLV_TYPE_EXT_WINDOW_ENUM_GROUP) do |w|
      windows << {
        pid: w.get_tlv_value(TLV_TYPE_EXT_WINDOW_ENUM_PID),
        handle: w.get_tlv_value(TLV_TYPE_EXT_WINDOW_ENUM_HANDLE),
        title: w.get_tlv_value(TLV_TYPE_EXT_WINDOW_ENUM_TITLE),
        class_name: w.get_tlv_value(TLV_TYPE_EXT_WINDOW_ENUM_CLASSNAME)
      }
    end

    windows.sort_by { |w| w[:pid] }
  end

  attr_accessor :client

end
end
end
end
end
end
end
