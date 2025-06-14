# -*- coding: binary -*-

require 'rex/post/process'
require 'rex/post/meterpreter/packet'
require 'rex/post/meterpreter/client'
require 'rex/post/meterpreter/extensions/stdapi/constants'
require 'rex/post/meterpreter/extensions/stdapi/stdapi'
require 'rex/post/meterpreter/extensions/stdapi/sys/event_log_subsystem/event_record'

module Rex
module Post
module Meterpreter
module Extensions
module Stdapi
module Sys

###
#
# This class provides access to the Windows event log on the remote
# machine.
#
###
class EventLog

  class << self
    attr_accessor :client
  end

  #
  # Opens the supplied event log.
  #
  #--
  # NOTE: should support UNCServerName sometime
  #++
  #
  def EventLog.open(name)
    request = Packet.create_request(COMMAND_ID_STDAPI_SYS_EVENTLOG_OPEN)

    request.add_tlv(TLV_TYPE_EVENT_SOURCENAME, name);

    response = client.send_request(request)

    return self.new(response.get_tlv_value(TLV_TYPE_EVENT_HANDLE))
  end

  ##
  #
  # Event Log Instance Stuffs!
  #
  ##

  attr_accessor :handle # :nodoc:
  attr_accessor :client # :nodoc:

  public

  #
  # Initializes an instance of the eventlog manipulator.
  #
  def initialize(hand)
    self.client = self.class.client
    self.handle = hand

    # Ensure the remote object is closed when all references are removed
    ObjectSpace.define_finalizer(self, self.class.finalize(client, hand))
  end

  def self.finalize(client,handle)
    proc do
      deferred_close_proc = proc do
        begin
          self.close(client,handle)
        rescue => e
          elog("finalize method for EventLog failed", error: e)
        end
      end

      # Schedule the finalizing logic out-of-band; as this logic might be called in the context of a Signal.trap, which can't synchronize mutexes
      client.framework.sessions.schedule(deferred_close_proc)
    end
  end

  #
  # Return the number of records in the event log.
  #
  def length
    request = Packet.create_request(COMMAND_ID_STDAPI_SYS_EVENTLOG_NUMRECORDS)

    request.add_tlv(TLV_TYPE_EVENT_HANDLE, self.handle);

    response = client.send_request(request)

    return response.get_tlv_value(TLV_TYPE_EVENT_NUMRECORDS)
  end

  #
  # the low level read function (takes flags, not hash, etc).
  #
  def _read(flags, offset = 0)
    request = Packet.create_request(COMMAND_ID_STDAPI_SYS_EVENTLOG_READ)

    request.add_tlv(TLV_TYPE_EVENT_HANDLE, self.handle)
    request.add_tlv(TLV_TYPE_EVENT_READFLAGS, flags)
    request.add_tlv(TLV_TYPE_EVENT_RECORDOFFSET, offset)

    response = client.send_request(request)

    EventLogSubsystem::EventRecord.new(
      response.get_tlv_value(TLV_TYPE_EVENT_RECORDNUMBER),
      response.get_tlv_value(TLV_TYPE_EVENT_TIMEGENERATED),
      response.get_tlv_value(TLV_TYPE_EVENT_TIMEWRITTEN),
      response.get_tlv_value(TLV_TYPE_EVENT_ID),
      response.get_tlv_value(TLV_TYPE_EVENT_TYPE),
      response.get_tlv_value(TLV_TYPE_EVENT_CATEGORY),
      response.get_tlv_values(TLV_TYPE_EVENT_STRING),
      response.get_tlv_value(TLV_TYPE_EVENT_DATA)
    )
  end

  #
  # Read the eventlog forwards, meaning from oldest to newest.
  # Returns a EventRecord, and throws an exception after no more records.
  #
  def read_forwards
    _read(EVENTLOG_SEQUENTIAL_READ | EVENTLOG_FORWARDS_READ)
  end

  #
  # Iterator for read_forwards.
  #
  def each_forwards
    begin
      loop do
        yield(read_forwards)
      end
    rescue ::Exception
    end
  end

  #
  # Read the eventlog backwards, meaning from newest to oldest.
  # Returns a EventRecord, and throws an exception after no more records.
  #
  def read_backwards
    _read(EVENTLOG_SEQUENTIAL_READ | EVENTLOG_BACKWARDS_READ)
  end

  #
  # Iterator for read_backwards.
  #
  def each_backwards
    begin
      loop do
        yield(read_backwards)
      end
    rescue ::Exception
    end
  end

  #
  # Return the record number of the oldest event (not necessarily 1).
  #
  def oldest
    request = Packet.create_request(COMMAND_ID_STDAPI_SYS_EVENTLOG_OLDEST)

    request.add_tlv(TLV_TYPE_EVENT_HANDLE, self.handle);

    response = client.send_request(request)

    return response.get_tlv_value(TLV_TYPE_EVENT_RECORDNUMBER)
  end

  #
  # Clear the specified event log (and return nil).
  #
  #--
  # I should eventually support BackupFile
  #++
  #
  def clear
    request = Packet.create_request(COMMAND_ID_STDAPI_SYS_EVENTLOG_CLEAR)

    request.add_tlv(TLV_TYPE_EVENT_HANDLE, self.handle);

    client.send_request(request)
    return self
  end

  #
  # Close the event log
  #
  def self.close(client, handle)
    request = Packet.create_request(COMMAND_ID_STDAPI_SYS_EVENTLOG_CLOSE)
    request.add_tlv(TLV_TYPE_EVENT_HANDLE, handle);
    client.send_request(request, nil)
    return nil
  end

  # Instance method
  def close
    unless self.handle.nil?
      ObjectSpace.undefine_finalizer(self)
      self.class.close(self.client, self.handle)
      self.handle = nil
    end
  end
end

end end end end end end
