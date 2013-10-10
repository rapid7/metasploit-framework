#!/usr/bin/env ruby
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

    windows.sort_by { |w| w[:pid] }
  end

  attr_accessor :client

end

end; end; end; end; end; end
