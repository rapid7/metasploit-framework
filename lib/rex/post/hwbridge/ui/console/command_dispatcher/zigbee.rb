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
      'supported_devices'   => 'Get supported ZigBee devices',
      'target' => 'Set the target device id',
      'channel' => 'Set the channel'
    }

    all
  end

  # Sets the target device both in the UI class and in the base API
  # @param device [String] Device ID
  def set_target_device(device)
    self.target_device = device
    client.zigbee.set_target_device device
  end

  #
  # Lists all thesupported devices
  #
  def cmd_supported_devices
    devices = client.zigbee.supported_devices
    if !devices or !devices.has_key? "devices"
      print_line("error retrieving list of devices")
      return
    end
    devices = devices["devices"]
    unless devices.size > 0
      print_line("none")
      return
    end
    set_target_device(devices[0]) if devices.size == 1
    str = "Supported Devices: "
    str << devices.join(', ')
    str << "\nUse device name to set your desired device, default is: #{self.target_device}"
    print_line(str)
  end

  #
  # Sets the default target device
  #
  def cmd_target(*args)
    self.target_device = ""
    device_opts = Rex::Parser::Arguments.new(
      '-h' => [ false, 'Help banner' ],
      '-d' => [ true, 'Device ID' ]
    )
    device_opts.parse(args) do |opt, _idx, val|
      case opt
      when '-h'
        print_line("Usage: target -d <device id>\n")
        print_line(device_opts.usage)
        return
      when '-d'
        set_target_device val
      end
    end
    print_line("set target device to #{self.target_device}")
  end

  #
  # Sets the channel
  #
  def cmd_channel(*args)
    chan = 11
    dev = self.target_device if self.target_device
    xopts = Rex::Parser::Arguments.new(
      '-h' => [ false, 'Help banner' ],
      '-d' => [ true, 'ZigBee device' ],
      '-c' => [ true, 'Channel number' ]
    )
    xopts.parse(args) do |opt, _idx, val|
      case opt
      when '-h'
        print_line("Usage: channel -c <channel number>\n")
        print_line(xopts.usage)
        return
      when '-d'
        dev = val
      when '-c'
        chan = val.to_i
      end
    end
    unless dev
      print_line("You must specify or set a target device")
      return
    end
    client.zigbee.set_channel(dev, chan)
    print_line("Device #{dev} channel set to #{chan}")
  end

  #
  # Name for this dispatcher
  #
  def name
    'Zigbee'
  end

  attr_accessor :target_device
end

end
end
end
end

