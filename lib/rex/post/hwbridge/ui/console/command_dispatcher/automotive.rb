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

  def initialize(shell)
    super
    self.tpjobs     = []
    self.tpjob_id   = 0
  end

  #
  # List of supported commands.
  #
  def commands
    all = {
      'supported_buses'   => 'Get supported buses',
      'busconfig'         => 'Get baud configs',
      'connect'           => 'Get HW supported methods for a bus',
      'cansend'           => 'Send a CAN packet',
      'isotpsend'         => 'Send an ISO-TP Packet and get a response',
      'testerpresent'     => 'Sends TesterPresent Pulses to the bus'
    }

    reqs = {
      'supported_buses'  => ['get_supported_buses'],
      'busconfig'        => ['get_bus_config'],
      'connect'          => ['get_supported_methods'],
      'cansend'          => ['cansend'],
      'testerpresent'    => ['testpresent']
    }

    # Ensure any requirements of the command are met
    all
  end

  #
  # Lists all thesupported buses
  #
  def cmd_supported_buses
    buses = client.automotive.get_supported_buses
    unless !buses.empty?
      print_line("none")
      return
    end
    str = "Available buses\n\n"
    first = true
    buses.each do |bus|
      unless first
        str += ", "
      end
      first = false
      str += bus["bus_name"] if bus.key? "bus_name"
    end
    str += "\n"
    print_line(str)
  end

  #
  # Retrives the current confiugration of a bus
  #
  def cmd_busconfig(*args)
    bus = ''
    bus_config_opts = Rex::Parser::Arguments.new(
      '-h' => [ false, 'Help banner' ],
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
    unless client.automotive.is_valid_bus? bus
      print_error("You must specify a valid bus via -b")
      return
    end
    config = client.automotive.get_bus_config(bus)
    config
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
    unless client.automotive.is_valid_bus? bus
      print_error("You must specify a valid bus via -b")
      print_line("Current active bus: #{self.active_bus}") if self.active_bus
      return
    end
    self.active_bus = bus
    client.automotive.set_active_bus(bus)
    hw_methods = client.automotive.get_supported_methods(bus)
    hw_methods
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
    bus = self.active_bus if bus.blank? && !self.active_bus.nil?
    unless client.automotive.is_valid_bus? bus
      print_error("You must specify a valid bus via -b")
      return
    end
    if id.blank? || data.blank?
      print_error("You must specify a CAN ID (-I) and the data packets (-D)")
      return
    end
    success = client.automotive.cansend(bus, id, data)
    success
  end

  #
  # Generic ISO-TP CAN send packet command
  #
  def cmd_isotpsend(*args)
    bus = ''
    id = ''
    ret = ''
    data = ''
    timeout = nil
    maxpackets = nil
    flowcontrol = false
    padding = nil
    cansend_opts = Rex::Parser::Arguments.new(
      '-h' => [ false, 'Help Banner' ],
      '-b' => [ true, 'Target bus'],
      '-I' => [ true, 'CAN ID'],
      '-R' => [ true, 'Return ID'],
      '-D' => [ true, 'Data packet in Hex (Do not include ISOTP command size)'],
      '-t' => [ true, 'Timeout value'],
      '-p' => [ true, 'Padding value, none if not specified'],
      '-C' => [ false, 'Force flow control'],
      '-m' => [ true, 'Max packets to receive']
    )
    cansend_opts.parse(args) do |opt, _idx, val|
      case opt
      when '-h'
        print_line("Usage: isotpsend -I <ID> -D <data>\n")
        print_line(cansend_opts.usage)
        return
      when '-b'
        bus = val
      when '-I'
        id = val
      when '-R'
        ret = val
      when '-D'
        data = val
      when '-t'
        timeout = val.to_i
      when '-p'
        padding = val
      when '-C'
        flowcontrol = true
      when '-m'
        maxpackets = val.to_i
      end
    end
    bus = self.active_bus if bus.blank? && !self.active_bus.nil?
    unless client.automotive.is_valid_bus? bus
      print_error("You must specify a valid bus via -b")
      return
    end
    if id.blank? || data.blank?
      print_error("You must specify a CAN ID (-I) and the data packets (-D)")
      return
    end
    if ret.blank?
      ret = (id.hex + 8).to_s(16)
      print_line("Default return set to #{ret}")
    end
    bytes = data.scan(/../)  # Break up data string into 2 char (byte) chunks
    if bytes.size > 8
      print_error("Data section can only contain a max of 8 bytes (for now)")
      return
    end
    opt = {}
    opt['TIMEOUT'] = timeout unless timeout.nil?
    opt['MAXPKTS'] = maxpackets unless maxpackets.nil?
    opt['PADDING'] = padding unless padding.nil?
    opt['FC'] = true unless flowcontrol == false
    result = client.automotive.send_isotp_and_wait_for_response(bus, id, ret, bytes, opt)
    if result.key? 'Packets'
      result['Packets'].each do |pkt|
        print_line pkt.inspect
      end
    end
    print_line(result['error'].inspect) if result.key? 'error'
    result
  end

  #
  # Sends TesterPresent packets as a background job
  #
  def cmd_testerpresent(*args)
    bus = ''
    id = ''
    stop = false
    stopid = 0
    tp_opts = Rex::Parser::Arguments.new(
      '-h' => [ false, 'Help Banner' ],
      '-b' => [ true, 'Target bus' ],
      '-I' => [ true, 'CAN ID' ],
      '-x' => [ true, 'Stop TesterPresent JobID']
    )
    tp_opts.parse(args) do |opt, _idx, val|
      case opt
      when '-h'
        print_line("Usage: testerpresent -I <ID>\n")
        print_line(tp_opts.usage)
        return
      when '-b'
        bus = val
      when '-I'
        id = val
      when '-x'
        stop = true
        stopid = val.to_i
      end
    end
    bus = self.active_bus if bus.blank? && !self.active_bus.nil?
    unless client.automotive.is_valid_bus? bus
      print_error("You must specify a valid bus via -b")
      return
    end
    if id.blank? && !stop
      if self.tpjobs.size > 0
        print_line("TesterPresent is currently active")
        self.tpjobs.each_index do |jid|
          if self.tpjobs[jid]
            print_status("TesterPresent Job #{jid}: #{self.tpjobs[jid][:args].inspect}")
          end
        end
      else
        print_line("TesterPreset is not active.  Use -I to start")
      end
      return
    end
    if stop
      if self.tpjobs[stopid]
        self.tpjobs[stopid].kill
        self.tpjobs[stopid] = nil
        print_status("Stopped TesterPresent #{stopid}")
      else
        print_error("TesterPresent #{stopid} was not running")
      end
    else
      jid = self.tpjob_id
      print_status("Starting TesterPresent sender (#{self.tpjob_id})")
      self.tpjob_id += 1
      self.tpjobs[jid] = Rex::ThreadFactory.spawn("TesterPresent(#{id})-#{jid}", false, jid, args) do |myjid,xargs|
        ::Thread.current[:args] = xargs.dup
        begin
          loop do
            client.automotive.cansend(bus, id, "023E00")
            sleep(2)
          end
        rescue ::Exception
          print_error("Error in TesterPResent: #{$!.class} #{$!}")
          elog("Error in TesterPreset: #{$!.class} #{$!}")
          dlog("Callstack: #{$@.join("\n")}")
        end
        self.tpjobs[myjid] = nil
        print_status("TesterPreset #{myjid} has stopped (#{::Thread.current[:args].inspect})")
      end
    end
  end

  #
  # Name for this dispatcher
  #
  def name
    'Automotive'
  end

  attr_accessor :active_bus

  protected

  attr_accessor :tpjobs, :tpjob_id # :nodoc:


end

end
end
end
end

