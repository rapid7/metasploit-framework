# -*- coding: binary -*-
require 'msf/core/module'

module Msf

###
#
# The auxiliary class acts as a base class for all modules that perform
# reconnaisance, retrieve data, brute force logins, or any other action
# that doesn't fit our concept of an 'exploit' (involving payloads and
# targets and whatnot).
#
###
class Auxiliary < Msf::Module

  require 'msf/core/auxiliary/mixins'

  include HasActions

  #
  # Returns MODULE_AUX to indicate that this is an auxiliary module.
  #
  def self.type
    MODULE_AUX
  end

  #
  # Returns MODULE_AUX to indicate that this is an auxiliary module.
  #
  def type
    MODULE_AUX
  end

  #
  # Creates an instance of the auxiliary module.
  #
  def initialize(info = {})

    # Call the parent constructor after making any necessary modifications
    # to the information hash.
    super(info)

    self.sockets = Array.new
    self.queue   = Array.new
  end

  #
  # Creates a singleton instance of this auxiliary class
  #
  def self.create(info = {})
    return @@aux_singleton if @@aux_singleton
    @@aux_singleton = self.new(info)
  end

  def run
    print_status("Running the default Auxiliary handler")
  end

  def auxiliary_commands
    return { }
  end

  #
  # Performs last-minute sanity checking of auxiliary parameters. This method
  # is called during automated exploitation attempts and allows an
  # auxiliary module to filter bad attempts, obtain more information, and choose
  # better parameters based on the available data. Returning anything that
  # evaluates to "false" will cause this specific auxiliary attempt to
  # be skipped. This method can and will change datastore values and
  # may interact with the backend database. The default value for auxiliary
  # modules is false, since not all auxiliary modules actually attempt
  # to exploit a vulnerability.
  #
  def autofilter
    false
  end

  #
  # Provides a list of ports that can be used for matching this module
  # against target systems.
  #
  def autofilter_ports
    @autofilter_ports || []
  end

  #
  # Provides a list of services that can be used for matching this module
  # against target systems.
  #
  def autofilter_services
    @autofilter_services || []
  end

  #
  # Adds a port into the list of ports
  #
  def register_autofilter_ports(ports=[])
    @autofilter_ports ||= []
    @autofilter_ports << ports
    @autofilter_ports.flatten!
    @autofilter_ports.uniq!
  end

  def register_autofilter_services(services=[])
    @autofilter_services ||= []
    @autofilter_services << services
    @autofilter_services.flatten!
    @autofilter_services.uniq!
  end


  #
  # Called directly before 'run'
  #
  def setup
  end

  #
  # Called after 'run' returns
  #
  def cleanup
    abort_sockets()
  end

  #
  # Adds a socket to the list of sockets opened by this exploit.
  #
  def add_socket(sock)
    self.sockets << sock
  end

  #
  # Removes a socket from the list of sockets.
  #
  def remove_socket(sock)
    self.sockets.delete(sock)
  end

  #
  # This method is called once a new session has been created on behalf of
  # this module instance and all socket connections created by this
  # module should be closed.
  #
  def abort_sockets
    sockets.delete_if { |sock|

      begin
        sock.close
      rescue ::Exception
      end
      true
    }
  end

  attr_accessor :queue

protected

  attr_accessor :sockets
  attr_writer :passive

end

end

