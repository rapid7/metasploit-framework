#!/usr/bin/env ruby
# -*- coding: binary -*-

require 'rex/post/meterpreter/extensions/extapi/tlv'

module Rex
module Post
module Meterpreter
module Extensions
module Extapi

###
#
# This meterpreter extension contains an extended API which will allow for more
#  advanced enumeration of the victim. This includes detail of:
#   * Active/open windows
#   * Services
#   * Clipboard
#   ... and more.
#
###
class Extapi < Extension

  def initialize(client)
    super(client, 'extapi')

    client.register_extension_aliases(
      [
        {
          'name' => 'extapi',
          'ext'  => self
        },
      ])
  end

  # Enumerate all the top-level windows on the target
  def window_enum()
    request = Packet.create_request('extapi_window_enum')
    response = client.send_request(request)

    windows = []

    response.each(TLV_TYPE_EXT_WINDOW_ENUM_GROUP) { |w|
      windows << {
        :pid    => w.get_tlv_value(TLV_TYPE_EXT_WINDOW_ENUM_PID),
        :handle => w.get_tlv_value(TLV_TYPE_EXT_WINDOW_ENUM_HANDLE),
        :title  => w.get_tlv_value(TLV_TYPE_EXT_WINDOW_ENUM_TITLE)
      }
    }

    return windows.sort_by { |w| w[:pid] }
  end

  # Enumerate all the services on the target.
  def service_enum()
    request = Packet.create_request('extapi_service_enum')
    response = client.send_request(request)

    services = []

    response.each(TLV_TYPE_EXT_SERVICE_ENUM_GROUP) { |s|
      services << {
        :name         => s.get_tlv_value(TLV_TYPE_EXT_SERVICE_ENUM_NAME),
        :display      => s.get_tlv_value(TLV_TYPE_EXT_SERVICE_ENUM_DISPLAYNAME),
        :pid          => s.get_tlv_value(TLV_TYPE_EXT_SERVICE_ENUM_PID),
        :status       => s.get_tlv_value(TLV_TYPE_EXT_SERVICE_ENUM_STATUS),
        :interactive  => s.get_tlv_value(TLV_TYPE_EXT_SERVICE_ENUM_INTERACTIVE)
      }
    }

    return services.sort_by { |s| s[:name].upcase }
  end

end

end; end; end; end; end
