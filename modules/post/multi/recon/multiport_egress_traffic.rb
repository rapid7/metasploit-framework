# -*- coding: binary -*-

##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  def initialize(info = {})
    super(update_info(info,
      'Name'         => 'Generate TCP/UDP Outbound Traffic On Multiple Ports',
      'Description'  => %q(
        This module generates TCP or UDP traffic across a
        sequence of ports, and is useful for finding firewall
        holes and egress filtering. It only generates traffic
        on the port range you specify. It is up to you to
        run a responder or packet capture tool on a remote
        endpoint to determine which ports are open.
      ),
      'License'      => MSF_LICENSE,
      'Author'       => 'Stuart Morgan <stuart.morgan[at]mwrinfosecurity.com>',
      'Platform'     => ['linux', 'osx', 'unix', 'solaris', 'bsd', 'windows'],
      'SessionTypes' => ['meterpreter']
      ))

    register_options(
      [
        OptAddress.new('TARGET', [true, 'Destination IP address.']),
        OptString.new('PORTS', [true, 'Ports to test.', '22,23,53,80,88,443,445,33434-33534']),
        OptEnum.new('PROTOCOL', [true, 'Protocol to use.', 'TCP', [ 'TCP', 'UDP', 'ALL' ]]),
        OptEnum.new('METHOD', [true, 'The mechanism by which the packets are generated. Can be NATIVE or WINAPI (Windows only).', 'NATIVE', [ 'NATIVE', 'WINAPI']]),
        OptInt.new('THREADS', [true, 'Number of simultaneous threads/connections to try.', '20'])
      ])
  end

  def winapi_create_socket(proto)
    if proto == 'TCP'
      client.railgun.ws2_32.socket('AF_INET', 'SOCK_STREAM', 'IPPROTO_TCP')
    elsif proto == 'UDP'
      client.railgun.ws2_32.socket('AF_INET', 'SOCK_DGRAM', 'IPPROTO_UDP')
    end
  end

  def native_init_connect(proto, ip, port, num, gw)
    vprint_status("[#{num}:NATIVE] Connecting to #{ip} port #{proto}/#{port}")
    if proto == 'TCP'
      begin
        Rex::Socket::Tcp.create(
          'Comm' => gw,
          'PeerHost' => ip,
          'PeerPort' => port
        )
      rescue
        vprint_status("[#{num}:NATIVE] Error connecting to #{ip} #{proto}/#{port}")
      end
    elsif proto == 'UDP'
      begin
        rudp = Rex::Socket::Udp.create(
          'Comm' => gw,
          'PeerHost' => ip,
          'PeerPort' => port
        )
        rudp.sendto('.', ip, port, 0) if rudp
      rescue
        vprint_status("[#{num}:NATIVE] Error connecting to #{ip} #{proto}/#{port}")
      end
    end
  end

  def winapi_make_connection(remote, dst_port, socket_handle, proto)
    sock_addr = "\x02\x00"
    sock_addr << [dst_port].pack('n')
    sock_addr << Rex::Socket.addr_aton(remote)
    sock_addr << "\x00" * 8
    return client.railgun.ws2_32.connect(socket_handle, sock_addr, 16) if proto == 'TCP'
    return client.railgun.ws2_32.sendto(socket_handle, ".", 0, 0, sock_addr, 16) if proto == 'UDP'
  end

  def run
    type = datastore['METHOD']
    remote = datastore['TARGET']
    thread_num = datastore['THREADS']
    proto = datastore['PROTOCOL']

    unless client.type == "meterpreter"
      print_error("This module requires meterpreter")
      return
    end

    # If we want WINAPI egress, make sure winsock is loaded
    if type == 'WINAPI'
      unless client.railgun.ws2_32 && client.platform == 'windows'
        print_error("The WINAPI method requires Windows, railgun and support for winsock APIs. Try using the NATIVE method instead.")
        return
      end
    end

    unless [ARCH_X64, ARCH_X86].include?(client.arch)
      print_error("This module cannot be used without native meterpreter at present")
      return
    end

    ports = Rex::Socket.portspec_crack(datastore['PORTS'])

    workload_ports = []
    workload_cycle = 0
    completed_cycle = false

    if thread_num > 1
      # Now we need to divvy up the ports into pots for each thread
      while !ports.nil? && !ports.empty?

        # If that group hasn't had its own ports array yet, give it some
        workload_ports[workload_cycle] = [] if workload_ports[workload_cycle].nil?

        # Add the port to the array to test
        workload_ports[workload_cycle] << ports.shift

        # Now increase the cycle until it goes above threads
        workload_cycle += 1
        if workload_cycle >= thread_num
          completed_cycle = true
          workload_cycle = 0
        end

      end

      if completed_cycle == false && thread_num > workload_cycle
        thread_num = workload_cycle
        vprint_status("Reduced threads to #{thread_num}.")
      else
        vprint_status("Number of threads: #{thread_num}.")
      end
    end

    gw = 0
    if type == 'NATIVE'
      unless (gw = framework.sessions.get(datastore['SESSION'])) && (gw.is_a?(Msf::Session::Comm))
        print_error("Error getting session to route egress traffic through to #{remote}")
        return
      end
    end

    str_proto = (proto == 'ALL') ? 'TCP and UDP' : proto

    print_status("Generating #{str_proto} traffic to #{remote}...")
    if thread_num > 1
      a = []
      0.upto(thread_num - 1) do |num|
        a << framework.threads.spawn("Module(#{refname})-#{remote}-#{proto}", false, workload_ports[num]) do |portlist|
          portlist.each do |dport|
            egress(type, proto, remote, dport, num, gw)
          end
        end
      end
      a.map(&:join)
    else
      ports.each do |dport|
        egress(type, proto, remote, dport, 1, gw)
      end
    end

    print_status("#{str_proto} traffic generation to #{remote} completed.")
  end

  # This will generate a single packet, selecting the correct methodology
  def egress(type, proto, remote, dport, num, gw)
    if type == 'WINAPI'
      if proto == 'ALL'
        winapi_egress_to_port('TCP', remote, dport, num)
        winapi_egress_to_port('UDP', remote, dport, num)
      else
        winapi_egress_to_port(proto, remote, dport, num)
      end
    elsif type == 'NATIVE'
      if proto == 'ALL'
        native_init_connect('TCP', remote, dport, num, gw)
        native_init_connect('UDP', remote, dport, num, gw)
      else
        native_init_connect(proto, remote, dport, num, gw)
      end
    end
  end

  # This will generate a packet on proto <proto> to IP <remote> on port <dport>
  def winapi_egress_to_port(proto, remote, dport, num)
    socket_handle = winapi_create_socket(proto)
    if socket_handle['return'] == 0
      vprint_status("[#{num}:WINAPI] Error setting up socket for #{remote}; Error: #{socket_handle['GetLastError']}")
      return
    else
      vprint_status("[#{num}:WINAPI] Set up socket for #{remote} port #{proto}/#{dport} (Handle: #{socket_handle['return']})")
    end

    vprint_status("[#{num}:WINAPI] Connecting to #{remote}:#{proto}/#{dport}")
    r = winapi_make_connection(remote, dport, socket_handle['return'], proto)
    if r['GetLastError'] == 0
      vprint_good("[#{num}:WINAPI] Connection packet sent successfully #{proto}/#{dport}")
    else
      vprint_bad("[#{num}:WINAPI] There was an error sending a connect packet for #{proto} socket (port #{dport}) Error: #{r['GetLastError']}")
    end

    client.railgun.ws2_32.closesocket(socket_handle['return'])
  end
end
