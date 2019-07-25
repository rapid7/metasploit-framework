# -*- coding: binary -*-
require 'msf/base'

module Msf
module Sessions

###
#
# This class provides the ability to receive a pingback UUID
#
###
class Pingback

  #
  # This interface supports basic interaction.
  #
  include Msf::Session
  include Msf::Session::Basic

  #
  # Returns the type of session.
  #
  def self.type
    "pingback"
  end

  def initialize(rstream, opts={})
    super
    self.platform ||= ""
    self.arch     ||= ""
    datastore = opts[:datastore]
  end

  def self.create_session(rstream, opts={})
    Msf::Sessions::Pingback.new(rstream, opts)
  end

  def process_autoruns(datastore)
    uuid_read
    cleanup
  end

  def cleanup
    if rstream
      # this is also a best-effort
      rstream.close rescue nil
      rstream = nil
    end
  end

  def uuid_read
    uuid_raw = rstream.get_once(16, 1)
    if uuid_raw
      self.uuid_string = uuid_raw.each_byte.map { |b| "%02x" % b.to_i() }.join
      print_status("Incoming UUID = #{uuid_string}")

      if framework.db.active
        begin
          payload = framework.db.payloads(uuid: uuid_string).first
          if payload.nil?
            print_warning("Provided UUID (#{uuid_string}) was not found in database!")
          else
            print_good("UUID identified (#{uuid_string})")
          end
        rescue ActiveRecord::ConnectionNotEstablished
          print_status("WARNING: UUID verification and logging is not available, because the database is not active.")
        rescue => e
          #TODO: Can we have a more specific exception handler?
          #       Test: what if we send no bytes back?  What if we send less than 16 bytes?  Or more than?
          print_bad("Can't get original UUID")
          print_bad("Exception Class: #{ e.class.name }")
          print_bad("Exception Message: #{ e.message }")
          print_bad("Exception Backtrace: #{ e.backtrace }")
        end
      else
        print_warning("WARNING: UUID verification and logging is not available, because the database is not active.")
      end
    end
    nil
  end
  #
  # Returns the session description.
  #
  def desc
    "Pingback"
  end

  #
  # Calls the class method
  #
  def type
    self.class.type
  end

  attr_accessor :arch
  attr_accessor :platform
  attr_accessor :uuid_string

end

end
end
