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
      $stderr.puts "Incoming UUID = #{uuid_string}"

      unless @db_active == false
        begin
          res = Mdm::Payload.find_by uuid: uuid_string

          # TODO: Output errors and UUID using something other than `puts`
          if res.nil?
            $stderr.puts("Provided UUID (#{uuid_string}) was not found in database!")
            #TODO: Abort, somehow?
          else
            $stderr.puts("UUID identified (#{uuid_string})")
          end
          @db_active = true
        rescue ActiveRecord::ConnectionNotEstablished
          @db_active = false
          $stderr.puts "WARNING: UUID verification and logging is not available, because the database is not active."
        rescue => e
          #TODO: Can we have a more specific exception handler?
          #       Test: what if we send no bytes back?  What if we send less than 16 bytes?  Or more than?
          $stderr.puts "Can't get original UUID"
          $stderr.puts "Exception Class: #{ e.class.name }"
          $stderr.puts "Exception Message: #{ e.message }"
          $stderr.puts "Exception Backtrace: #{ e.backtrace }"
        end
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
