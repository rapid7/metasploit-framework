##
# $Id$
##

##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/framework/
##

# $Revision$

module Msf

class Plugin::PcapLog < Msf::Plugin

  # Only little-endian is supported in this implementation.
  PCAP_FILE_HEADER = "\xD4\xC3\xB2\xA1\x02\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00`\x00\x00\x00\x01\x00\x00\x00"

  #
  # Implements a pcap console command dispatcher.
  #
  class PcapLogDispatcher

    include Msf::Ui::Console::CommandDispatcher

    def name
      "PcapLog"
    end

    def commands
      {
        "pcap_filter" => "Set/Get a BPF-style packet filter",
        "pcap_dir"    => "Set/Get a directory to log pcaps to",
        "pcap_prefix" => "Set/Get a filename prefix to log pcaps to",
        "pcap_iface"  => "Set/Get an interface to capture from",
        "pcap_start"  => "Start a capture",
        "pcap_stop"   => "Stop a running capture",

        "pcap_show_config"  => "Show the current PcapLog configuration"
      }
    end

    def cmd_pcap_filter(*args)
      @filter = args.join(' ') || @filter
      print_line "#{self.name} BPF filter: #{@filter}"
    end

    def cmd_pcap_prefix(*args)
      @prefix = args[0] || @prefix || "msf3-session"
      print_line "#{self.name} prefix: #{@prefix}"
    end

    def cmd_pcap_dir(*args)
      @dir = args[0] || @dir || "/tmp"
      print_line "#{self.name} Directory: #{@dir}"
    end

    def cmd_pcap_iface(*args)
      @iface = args[0] || @iface
      print_line "#{self.name} Interface: #{@iface}"
    end

    def cmd_pcap_start(*args)

      unless @pcaprub_loaded 
        print_error("Pcap module not available")
        return false
      end

      if @capture_thread && @capture_thread.alive?
        print_error "Capture already started."
        return false
      end

      gen_fname
      print_line "Starting packet capture from #{@iface} to #{@fname}"
      okay,msg = validate_options
      unless okay
        print_error msg
        return false
      end
      dev = (@iface || ::Pcap.lookupdev)
      @capture_file.write(PCAP_FILE_HEADER)
      @capture_file.flush
      @pcap = ::Pcap.open_live(dev, 65535, true, 1)
      @pcap.setfilter(@filter) if @filter
      @capture_thread = Thread.new {
        @pcap.each do |pkt|
          @capture_file.write(convert_to_pcap(pkt))
          @capture_file.flush
        end
      }
    end

    def cmd_pcap_stop(*args)
      if @capture_thread && @capture_thread.alive?
        print_line "Stopping packet capture from #{@iface} to #{@fname}"
        print_line "Capture Stats: #{@pcap.stats.inspect}"
        @pcap = nil
        @capture_file.close if @capture_file.respond_to? :close
        @capture_thread.kill
        @capture_thread = nil
      else
        print_error "No capture running."
      end
    end

    def convert_to_pcap(packet)
      t = Time.now
      sz = packet.size
      [t.to_i, t.usec, sz, sz, packet].pack("V4A*")
    end

    def gen_fname
      t = Time.now
      file_part = "%s_%04d-%02d-%02d_%02d-%02d-%02d.pcap" % [
        @prefix, t.year, t.month, t.mday, t.hour, t.min, t.sec
      ]
      @fname = File.join(@dir, file_part)
    end

    # Check for euid 0 and check for a valid place to write files
    def validate_options

      # Check for root.
      unless Process.euid.zero?
        msg = "You must run as root in order to capture packets."
        return [false, msg]
      end

      # Check directory suitability.
      unless File.directory? @dir
        msg = "Invalid pcap directory specified: '#{@dir}'"
        return [false, msg]
      end

      unless File.writable? @dir
        msg = "No write permission to directory: '#{@dir}'"
        return [false, msg]
      end

      @capture_file = File.open(@fname, "ab")
      unless File.writable? @fname
        msg = "Cannot write to file: '#{@fname}'"
        return [false, msg]
      end

      # If you got this far, you're golden.
      msg = "We're good!"
      return [true, msg]
    end

    # Need to pretend to have a datastore for Exploit::Capture to
    # function.
    def datastore
      {}
    end

    def initialize(*args)
      super
      @dir = File.join(Msf::Config.config_directory, 'logs')
      @prefix = "msf3-session"
      @filter = nil
      @pcaprub_loaded = false
      begin
        require 'pcaprub'
        @pcaprub_loaded = true
        @iface = ::Pcap.lookupdev
      rescue ::Exception => e
        print_error "#{e.class}: #{e}"
        @pcaprub_loaded = false
        @pcaprub_error = e
      end
    end

  end

  def initialize(framework, opts)
    super
    add_console_dispatcher(PcapLogDispatcher)
    print_status "PcapLog plugin loaded."
  end

  # Kill the background thread
  def cleanup
    @capture_thread.kill if @capture_thread && @capture_thread.alive?
    @capture_file.close if @capture_file.respond_to? :close
    remove_console_dispatcher('PcapLog')
  end

  def name
    "pcap_log"
  end

  def desc
    "Logs all socket operations to pcaps (in /tmp by default)"
  end

end
end
