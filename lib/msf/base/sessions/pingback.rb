# -*- coding: binary -*-
require 'msf/base'

module Msf
module Sessions

###
#
# This class provides basic interaction with a command shell on the remote
# endpoint.  This session is initialized with a stream that will be used
# as the pipe for reading and writing the command shell.
#
###
class Pingback

  #
  # This interface supports basic interaction.
  #
  include Msf::Session::Basic

  #
  # Returns the type of session.
  #
  def self.type
    "pingback"
  end

  def initialize(conn, opts = {})
    self.platform ||= ""
    self.arch     ||= ""
    datastore = opts[:datastore]
    super
  end

  def self.create_session(conn, opts = {})
    uuid_raw = conn.get_once(16, 1)
    if uuid_raw
      uuid_string = uuid_raw.each_byte.map { |b| "%02x" % b.to_i() }.join
      puts("Incoming Pingback_UUID = |" + uuid_string + "|")

      res = Mdm::Payload.find_by uuid: uuid_string
      require 'pry'; binding.pry

      begin
        if res.nil?
          puts("Provided UUID (#{uuid_string}) was not found in database!")
          #TODO: Abort, somehow?
        else
          puts("UUID identified (#{uuid_string})")
        end
      rescue => e
        #TODO: Can we have a more specific exception handler?
        #       Test: what if we send no bytes back?  What if we send less than 16 bytes?  Or more than?
        puts "Can't get original UUID"
        puts "Exception Class: #{ e.class.name }"
        puts "Exception Message: #{ e.message }"
        puts "Exception Backtrace: #{ e.backtrace }"
      end
      conn.close
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

end

end
end
