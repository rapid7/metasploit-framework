# -*- coding: binary -*-

require 'rex/post/meterpreter/extensions/stdapi/stdapi'

module Rex
module Post
module Meterpreter
module Extensions
module Stdapi
module Fs

class Mount

  # Used when matching against windows drive types
  DRIVE_TYPES = [
    :unknown,
    :no_root,
    :removable,
    :fixed,
    :remote,
    :cdrom,
    :ramdisk
  ]

  def initialize(client)
    self.client = client
  end

  def show_mount
    request = Packet.create_request('stdapi_fs_mount_show')

    response = client.send_request(request)

    results = []

    response.each(TLV_TYPE_MOUNT) do |d|
      results << {
        name:        d.get_tlv_value(TLV_TYPE_MOUNT_NAME),
        type:        DRIVE_TYPES[d.get_tlv_value(TLV_TYPE_MOUNT_TYPE)],
        user_space:  d.get_tlv_value(TLV_TYPE_MOUNT_SPACE_USER),
        total_space: d.get_tlv_value(TLV_TYPE_MOUNT_SPACE_TOTAL),
        free_space:  d.get_tlv_value(TLV_TYPE_MOUNT_SPACE_FREE),
        unc:         d.get_tlv_value(TLV_TYPE_MOUNT_UNCPATH)
      }
    end

    results
  end

protected
  attr_accessor :client # :nodoc:

end

end; end; end; end; end; end


