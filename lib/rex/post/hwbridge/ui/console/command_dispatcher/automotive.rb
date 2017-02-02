# -*- coding: binary -*-
require 'rex/post/hwbridge'
require 'msf/core/auxiliary/report'

module Rex
module Post
module HWBridge
module Ui
###
# Automotive extension - set of commands to be executed on CAN bus
###
class Console::CommandDispatcher::Automotive
  include Console::CommandDispatcher
  include Msf::Auxiliary::Report

  #
  # List of supported commands.
  #
  def commands
    all = {
      'supported_buses'   => 'Get supported buses',
      'busconfig'         => 'Get buad configs',
      'connect'           => 'Get HW supported methods for a bus',
      'cansend'           => 'Send a CAN packet'
    }

    reqs = {
      'supported_buses'  => ['get_supported_buses'],
      'busconfig'        => ['get_bus_config'],
      'connect'          => ['get_supported_methods'],
      'cansend'          => ['cansend']
    }

    # Ensure any requirements of the command are met
#    all.delete_if do |cmd, _desc|
#      reqs[cmd].any? { |req| !client.commands.include?(req) }
#    end
    all
  end

  #
  # Lists all thesupported buses
  #
  def cmd_supported_buses
    buses = client.automotive.get_supported_buses
    if not buses.size > 0
      print_line("none")
      return
    end
    str = "Available buses\n\n"
    first = true
    buses.each do |bus|
      if not first
        str += ", "
      end
      first = false
      str += bus["bus_name"] if bus.has_key? "bus_name"
    end
    str+="\n"
    print_line(str)
  end

  #
  # Retrives the current confiugration of a bus
  #
  def cmd_busconfig(*args)
    bus = ''
    bus_config_opts = Rex::Parser::Arguments.new(
      '-h' => [ false, 'Help Banner' ],
      '-b' => [ true, 'Target bus']
    )
    bus_config_opts.parse(args) do |opt, _idx, val|
      case opt
      when '-h'
        print_line("Usage: bus_config -b <busname>\n")
        print_line(bus_config_opts.usage)
        return
      when '-b'
        bus = val
      end
    end
    if not client.automotive.is_valid_bus? bus
      print_error("You must specify a valid bus via -b")
      return
    end
    config = client.automotive.get_bus_config(bus)
  end

  #
  # 'connects' to a bus, this retrives the supported_methods
  # specific to this bus
  #
  def cmd_connect(*args)
    bus = ''
    connect_opts = Rex::Parser::Arguments.new(
      '-h' => [ false, 'Help Banner' ],
      '-b' => [ true, 'Target bus']
    )
    connect_opts.parse(args) do |opt, _idx, val|
      case opt
      when '-h'
        print_line("Usage: connect -b <busname>\n")
        print_line(connect_opts.usage)
        return
      when '-b'
        bus = val
      end
    end
    if not client.automotive.is_valid_bus? bus
      print_error("You must specify a valid bus via -b")
      return
    end
    self.active_bus = bus
    client.automotive.set_active_bus(bus)
    hw_methods = client.automotive.get_supported_methods(bus)
  end

  #
  # Generic CAN send packet command
  #
  def cmd_cansend(*args)
    bus = ''
    id = ''
    data = ''
    cansend_opts = Rex::Parser::Arguments.new(
      '-h' => [ false, 'Help Banner' ],
      '-b' => [ true, 'Target bus'],
      '-I' => [ true, 'CAN ID'],
      '-D' => [ true, 'Data packet in Hex']
    )
    cansend_opts.parse(args) do |opt, _idx, val|
      case opt
      when '-h'
        print_line("Usage: cansend -I <ID> -D <data>\n")
        print_line(cansend_opts.usage)
        return
      when '-b'
        bus = val
      when '-I'
        id = val
      when '-D'
        data = val
      end
    end
    bus = self.active_bus if bus.blank? and not self.active_bus == nil
    if not client.automotive.is_valid_bus? bus
      print_error("You must specify a valid bus via -b")
      return
    end
    if id.blank? or data.blank?
      print_error("You must specify a CAN ID (-I) and the data packets (-D)")
      return
    end
    success = client.automotive.cansend(bus, id, data)
  end

  #
  # Name for this dispatcher
  #
  def name
    'Automotive'
  end

private
  attr_accessor :active_bus

end

end
end
end
end

