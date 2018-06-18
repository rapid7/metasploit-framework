##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

##
# dsniff was helping me very often. Too bad that it doesn't work correctly
# anymore. Psnuffle should bring password sniffing into Metasploit local
# and if we get lucky even remote.
#
# Cheers - Max Moser - mmo@remote-exploit.org
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Auxiliary::Report
  include Msf::Exploit::Capture

  def initialize
    super(
      'Name'        => 'pSnuffle Packet Sniffer',
      'Description' => 'This module sniffs passwords like dsniff did in the past',
      'Author'	    => 'Max Moser <mmo[at]remote-exploit.org>',
      'License'	    => MSF_LICENSE,
      'Actions'	    =>
        [
          [ 'Sniffer' ],
          [ 'List' ]
        ],
      'PassiveActions' => [ 'Sniffer' ],
      'DefaultAction'  => 'Sniffer'
    )
    register_options [
      OptString.new('PROTOCOLS', [true, 'A comma-delimited list of protocols to sniff or "all".', 'all']),
    ]

    register_advanced_options [
      OptPath.new('ProtocolBase', [true, 'The base directory containing the protocol decoders',
        File.join(Msf::Config.data_directory, 'exploits', 'psnuffle')
      ]),
    ]
    deregister_options('RHOST', 'RHOSTS')
  end


  def load_protocols
    base = datastore['ProtocolBase']
    unless File.directory? base
      raise RuntimeError, 'The ProtocolBase parameter is set to an invalid directory'
    end

    allowed = datastore['PROTOCOLS'].split(',').map{|x| x.strip.downcase}
    @protos = {}
    decoders = Dir.new(base).entries.grep(/\.rb$/).sort
    decoders.each do |n|
      f = File.join(base, n)
      m = ::Module.new
      begin
        m.module_eval(File.read(f, File.size(f)))
        m.constants.grep(/^Sniffer(.*)/) do
          proto = $1
          next unless allowed.include?(proto.downcase) || datastore['PROTOCOLS'] == 'all'

          klass = m.const_get("Sniffer#{proto}")
          @protos[proto.downcase] = klass.new(framework, self)

          print_status("Loaded protocol #{proto} from #{f}...")
        end
      rescue => e
        print_error("Decoder #{n} failed to load: #{e.class} #{e} #{e.backtrace}")
      end
    end
  end

  def run
    check_pcaprub_loaded # Check first
    # Load all of our existing protocols
    load_protocols

    if action.name == 'List'
      print_status("Protocols: #{@protos.keys.sort.join(', ')}")
      return
    end

    print_status 'Sniffing traffic.....'
    open_pcap

    each_packet do |pkt|
      p = PacketFu::Packet.parse(pkt)
      next unless p.is_tcp?
      next if p.payload.empty?
      @protos.each_key do |k|
        @protos[k].parse(p)
      end
      true
    end
    close_pcap
    print_status 'Finished sniffing'
  end
end

# End module class

# Basic class for taking care of sessions
class BaseProtocolParser

  attr_accessor :framework, :module, :sessions, :dport, :sigs

  def initialize(framework, mod)
    self.framework = framework
    self.module    = mod
    self.sessions  = {}
    self.dport     = 0
    register_sigs
  end

  def parse(pkt)
    nil
  end

  def register_sigs
    self.sigs = {}
  end

  #
  # Glue methods to bridge parsers to the main module class
  #
  def print_status(msg)
    self.module.print_status(msg)
  end

  def print_error(msg)
    self.module.print_error(msg)
  end

  def report_auth_info(*s)
    self.module.report_auth_info(*s)
  end

  def report_note(*s)
    self.module.report_note(*s)
  end

  def report_service(*s)
    self.module.report_service(*s)
  end

  def find_session(sessionid)
    purge_keys = []
    sessions.each_key do |ses|
      # Check for cleanup abilities... kills performance in large environments maybe
      # When longer than 5 minutes no packet was related to the session, delete it
      if ((sessions[ses][:mtime] - sessions[ses][:ctime]) > 300)
        # too bad to this session has no action for a long time
        purge_keys << ses
      end
    end
    purge_keys.each {|ses| sessions.delete(ses) }

    # Does this session already exist?
    if (sessions[sessionid])
      # Refresh the timestamp
      sessions[sessionid][:mtime] = Time.now
    else
      # Create a new session entry along with the host/port from the id
      if (sessionid =~ /^([^:]+):([^-]+)-([^:]+):(\d+)$/s)
        sessions[sessionid] = {
          :client_host => $1,
          :client_port => $2,
          :host        => $3,
          :port        => $4,
          :session     => sessionid,
          :ctime       => Time.now,
          :mtime       => Time.now
        }
      end
    end

    sessions[sessionid]
  end

  def get_session_src(pkt)
    return "%s:%d-%s:%d" % [pkt.ip_daddr,pkt.tcp_dport,pkt.ip_saddr,pkt.tcp_sport] if pkt.is_tcp?
    return "%s:%d-%s:%d" % [pkt.ip_daddr,pkt.udp_dport,pkt.ip_saddr,pkt.udp_sport] if pkt.is_udp?
    return "%s:%d-%s:%d" % [pkt.ip_daddr,0,pkt.ip_saddr,0]
  end

  def get_session_dst(pkt)
    return "%s:%d-%s:%d" % [pkt.ip_saddr,pkt.tcp_sport,pkt.ip_daddr,pkt.tcp_dport] if pkt.is_tcp?
    return "%s:%d-%s:%d" % [pkt.ip_saddr,pkt.udp_sport,pkt.ip_daddr,pkt.udp_dport] if pkt.is_udp?
    return "%s:%d-%s:%d" % [pkt.ip_saddr,0,pkt.ip_daddr,0]
  end
end
