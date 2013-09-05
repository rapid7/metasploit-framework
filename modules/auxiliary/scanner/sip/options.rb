##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##


require 'msf/core'


class Metasploit3 < Msf::Auxiliary

  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Scanner

  def initialize
    super(
      'Name'        => 'SIP Endpoint Scanner (UDP)',
      'Description' => 'Scan for SIP devices using OPTIONS requests',
      'Author'      => 'hdm',
      'License'     => MSF_LICENSE
    )

    register_options(
    [
      OptInt.new('BATCHSIZE', [true, 'The number of hosts to probe in each set', 256]),
      OptString.new('TO',   [ false, "The destination username to probe at each host", "nobody"]),
      Opt::RPORT(5060),
      Opt::CHOST,
      Opt::CPORT(5060)
    ], self.class)
  end


  # Define our batch size
  def run_batch_size
    datastore['BATCHSIZE'].to_i
  end

  # Operate on an entire batch of hosts at once
  def run_batch(batch)

    begin
      udp_sock = nil
      idx = 0

      # Create an unbound UDP socket if no CHOST is specified, otherwise
      # create a UDP socket bound to CHOST (in order to avail of pivoting)
      udp_sock = Rex::Socket::Udp.create(
        {
          'LocalHost' => datastore['CHOST'] || nil,
          'LocalPort' => datastore['CPORT'].to_i,
          'Context' => {'Msf' => framework, 'MsfExploit' => self}
        }
      )
      add_socket(udp_sock)

      batch.each do |ip|
        data = create_probe(ip)

        begin
          udp_sock.sendto(data, ip, datastore['RPORT'].to_i, 0)
        rescue ::Interrupt
          raise $!
        rescue ::Rex::HostUnreachable, ::Rex::ConnectionTimeout, ::Rex::ConnectionRefused
          nil
        end

        if (idx % 10 == 0)
          while (r = udp_sock.recvfrom(65535, 0.01) and r[1])
            parse_reply(r)
          end
        end

        idx += 1
      end

      while (r = udp_sock.recvfrom(65535, 3) and r[1])
        parse_reply(r)
      end

    rescue ::Interrupt
      raise $!
    rescue ::Exception => e
      print_error("Unknown error: #{e.class} #{e}")
    ensure
      udp_sock.close if udp_sock
    end
  end

  #
  # The response parsers
  #
  def parse_reply(pkt)

    return if not pkt[1]

    if(pkt[1] =~ /^::ffff:/)
      pkt[1] = pkt[1].sub(/^::ffff:/, '')
    end

    resp  = pkt[0].split(/\s+/)[1]
    agent = ''
    verbs = ''
    serv  = ''
    prox  = ''

    if(pkt[0] =~ /^User-Agent:\s*(.*)$/i)
      agent = "agent='#{$1.strip}' "
    end

    if(pkt[0] =~ /^Allow:\s+(.*)$/i)
      verbs = "verbs='#{$1.strip}' "
    end

    if(pkt[0] =~ /^Server:\s+(.*)$/)
      serv = "server='#{$1.strip}' "
    end

    if(pkt[0] =~ /^Proxy-Require:\s+(.*)$/)
      serv = "proxy-required='#{$1.strip}' "
    end

    print_status("#{pkt[1]} #{resp} #{agent}#{serv}#{prox}#{verbs}")

    report_service(
      :host   => pkt[1],
      :port   => pkt[2],
      :proto  => 'udp',
      :name   => 'sip'
    )

    if(not agent.empty?)
      report_note(
        :host   => pkt[1],
        :type  => 'sip_useragent',
        :data   => agent
      )
    end
  end

  def create_probe(ip)
    suser = Rex::Text.rand_text_alphanumeric(rand(8)+1)
    shost = Rex::Socket.source_address(ip)
    src   = "#{shost}:#{datastore['CPORT']}"

    data  = "OPTIONS sip:#{datastore['TO']}@#{ip} SIP/2.0\r\n"
    data << "Via: SIP/2.0/UDP #{src};branch=z9hG4bK.#{"%.8x" % rand(0x100000000)};rport;alias\r\n"
    data << "From: sip:#{suser}@#{src};tag=70c00e8c\r\n"
    data << "To: sip:#{datastore['TO']}@#{ip}\r\n"
    data << "Call-ID: #{rand(0x100000000)}@#{shost}\r\n"
    data << "CSeq: 1 OPTIONS\r\n"
    data << "Contact:  sip:#{suser}@#{src}\r\n"
    data << "Content-Length: 0\r\n"
    data << "Max-Forwards: 20\r\n"
    data << "User-Agent: #{suser}\r\n"
    data << "Accept: text/plain\r\n"
  end


end
