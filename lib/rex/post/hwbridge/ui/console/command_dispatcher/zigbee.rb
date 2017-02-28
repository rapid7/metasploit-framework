# -*- coding: binary -*-
require 'rex/post/hwbridge'
require 'msf/core/auxiliary/report'

module Rex
module Post
module HWBridge
module Ui
###
# Zigbee extension - set of commands to be executed on Zigbee compatible devices
###
class Console::CommandDispatcher::Zigbee
  include Console::CommandDispatcher
  include Msf::Auxiliary::Report

  #
  # List of supported commands.
  #
  def commands
    all = {
      'supported_devices'   => 'Get supported zigbee devices'
    }

    all
  end

  #
  # Lists all thesupported devices
  #
  def cmd_supported_devices
    devices = client.zigbee.supported_devices
    if not devices or not devices.has_key? "devices"
      print_line("error retrieving list of devices")
      return
    end
    devices = devices["devices"]
    if not devices.size > 0
      print_line("none")
      return
    end
    self.target_device = devices[0] if devices.size == 1
    str = "Supported Devices: "
    str += devices.join(', ')
    str += "\nUse device name to set your desired device, default is: #{self.target_device}"
    print_line(str)
  end

  #
  # Sets the default target device
  #
  def cmd_target(*args)
    self.target_device = ""
    device_opts = Rex::Parser::Arguments.new(
      '-h' => [ false, 'Help Banner' ],
      '-d' => [ true, 'Device ID' ]
    )
    device_opts.parse(args) do |opt, _idx, val|
      case opt
      when '-h'
        print_line("Usage: target -d <device id>\n")
        print_line(device_opts.usage)
        return
      when '-d'
        self.target_device = val
      end
    end
    print_line("set target device to #{self.target_device}")
  end

  #
  # Name for this dispatcher
  #
  def name
    'Zigbee'
  end

private
  attr_accessor :target_device

end

end
end
end
end

