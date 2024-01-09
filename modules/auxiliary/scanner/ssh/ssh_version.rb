##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'recog'
require 'net/ssh/transport/session'

class MetasploitModule < Msf::Auxiliary
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report

  def initialize
    super(
      'Name' => 'SSH Version Scanner',
      'Description' => 'Detect SSH Version, and the algorithms available from the server',
      'References' => [
        ['URL', 'https://en.wikipedia.org/wiki/SecureShell'], # general info
        ['URL', 'https://datatracker.ietf.org/doc/html/rfc8732#name-deprecated-algorithms'], # deprecation of kex gss-sha1 stuff
        ['URL', 'https://datatracker.ietf.org/doc/html/draft-ietf-curdle-ssh-kex-sha2-20#page-16'], # diffie-hellman-group-exchange-sha1, diffie-hellman-group1-sha1, rsa1024-sha1
        ['URL', 'https://datatracker.ietf.org/doc/html/rfc8758#name-iana-considerations'], # arc4 deprecation
        ['URL', 'https://github.com/net-ssh/net-ssh?tab=readme-ov-file#supported-algorithms'] # a bunch of diff removed things from the ruby lib
      ],
      'Author' => [
        'Daniel van Eeden <metasploit[at]myname.nl>', # original author
        'h00die' # algorithms enhancements
      ],
      'License' => MSF_LICENSE
    )

    register_options(
      [
        Opt::RPORT(22),
        OptInt.new('TIMEOUT', [true, 'Timeout for the SSH probe', 30])
      ],
      self.class
    )
  end

  def timeout
    datastore['TIMEOUT']
  end

  def rport
    datastore['RPORT']
  end

  def run_host(target_host)
    ::Timeout.timeout(timeout) do
      transport = Net::SSH::Transport::Session.new(target_host, { port: rport })

      server_data = transport.algorithms.instance_variable_get(:@server_data)
      host_keys = transport.algorithms.session.instance_variable_get(:@host_keys).instance_variable_get(:@host_keys)
      if !host_keys.empty?
        print_status("Key Fingerprint: #{host_keys[0].fingerprint}")
      end

      ident = transport.server_version.version

      table = Rex::Text::Table.new(
        'Header' => 'Server Encryption',
        'Indent' => 2,
        'SortIndex' => 0,
        'Columns' => [ 'Type', 'Value']
      )

      server_data[:language_server].each do |language|
        table << ['Language', language]
      end

      server_data[:compression_server].each do |compression|
        table << ['Compression', compression]
      end

      server_data[:encryption_server].each do |encryption|
        ['arcfour', 'arcfour128', 'arcfour256'].each do |bad_enc|
          next unless encryption.downcase.start_with? bad_enc

          print_good("Encryption #{encryption} is deprecated and should not be used.")
          report_vuln(
            host: target_host,
            port: rport,
            proto: 'tcp',
            name: name,
            info: "Module #{fullname} confirmed SSH Encryption #{encryption} is available, but should be deprecated",
            refs: ['https://datatracker.ietf.org/doc/html/rfc8758#name-iana-considerations']
          )
        end
        [
          'aes256-cbc', 'aes192-cbc', 'aes128-cbc', 'rijndael-cbc@lysator.liu.se',
          'blowfish-ctr blowfish-cbc', 'cast128-ctr', 'cast128-cbc', '3des-ctr', '3des-cbc', 'idea-cbc', 'none'
        ].each do |bad_enc|
          next unless encryption.downcase.start_with? bad_enc

          print_good("Encryption #{encryption} is deprecated and should not be used.")
          report_vuln(
            host: target_host,
            port: rport,
            proto: 'tcp',
            name: name,
            info: "Module #{fullname} confirmed SSH Encryption #{encryption} is available, but should be deprecated",
            refs: ['https://github.com/net-ssh/net-ssh?tab=readme-ov-file#encryption-algorithms-ciphers']
          )
        end
        table << ['Encryption', encryption]
      end

      server_data[:hmac_server].each do |hmac|
        ['hmac-sha2-512-96', 'hmac-sha2-256-96', 'hmac-sha1-96', 'hmac-ripemd160', 'hmac-md5', 'hmac-md5-96', 'none'].each do |bad_hmac|
          next unless hmac.downcase.start_with? bad_hmac

          print_good("HMAC #{hmac} is deprecated and should not be used.")
          report_vuln(
            host: target_host,
            port: rport,
            proto: 'tcp',
            name: name,
            info: "Module #{fullname} confirmed SSH HMAC #{hmac} is available, but should be deprecated",
            refs: ['https://github.com/net-ssh/net-ssh?tab=readme-ov-file#message-authentication-code-algorithms']
          )
        end
        table << ['HMAC', hmac]
      end

      server_data[:host_key].each do |host_key|
        ['ecdsa-sha2-nistp521', 'ecdsa-sha2-nistp384', 'ecdsa-sha2-nistp256'].each do |bad_key|
          next unless host_key.downcase.start_with? bad_key

          print_good("Host Key Encryption #{host_key} uses a weak elliptic curve and should not be used.")
          report_vuln(
            host: target_host,
            port: rport,
            proto: 'tcp',
            name: name,
            info: "Module #{fullname} confirmed SSH Host Key Encryption #{host_key} is available, but should be deprecated",
            refs: ['https://github.com/net-ssh/net-ssh?tab=readme-ov-file#host-keys']
          )
        end
        table << ['Host Key', host_key]
      end

      server_data[:kex].each do |kex|
        ['gss-group1-sha1-', 'gss-group14-sha1-', 'gss-gex-sha1-'].each do |bad_kex|
          next unless kex.downcase.start_with? bad_kex

          print_good("Key Exchange (kex) #{kex} is deprecated and should not be used.")
          report_vuln(
            host: target_host,
            port: rport,
            proto: 'tcp',
            name: name,
            info: "Module #{fullname} confirmed SSH Encryption #{kex} is available, but should be deprecated",
            refs: ['https://datatracker.ietf.org/doc/html/rfc8732#name-deprecated-algorithms']
          )
        end
        ['ecdsa-sha2-nistp521', 'ecdsa-sha2-nistp384', 'ecdsa-sha2-nistp256'].each do |bad_kex|
          next unless kex.downcase.start_with? bad_kex

          print_good("Key Exchange (kex) #{kex} uses a weak elliptic curve and should not be used.")
          report_vuln(
            host: target_host,
            port: rport,
            proto: 'tcp',
            name: name,
            info: "Module #{fullname} confirmed SSH Encryption #{kex} is available, but should be deprecated",
            refs: ['https://github.com/net-ssh/net-ssh?tab=readme-ov-file#key-exchange']
          )
        end
        ['diffie-hellman-group-exchange-sha1', 'diffie-hellman-group1-sha1', 'rsa1024-sha1'].each do |bad_kex|
          next unless kex.downcase.start_with? bad_kex

          print_good("Key Exchange (kex) #{kex} is deprecated and should not be used.")
          report_vuln(
            host: target_host,
            port: rport,
            proto: 'tcp',
            name: name,
            info: "Module #{fullname} confirmed SSH Encryption #{kex} is available, but should be deprecated",
            refs: ['https://datatracker.ietf.org/doc/html/draft-ietf-curdle-ssh-kex-sha2-20#page-16']
          )
        end
        table << ['Key Exchange (kex)', kex]
      end

      # XXX check for host key size?
      # https://www.tenable.com/plugins/nessus/153954

      # Try to match with Recog and show the relevant fields to the user
      info = ''
      if /^SSH-\d+\.\d+-(.*)$/ =~ ident
        recog_match = Recog::Nizer.match('ssh.banner', ::Regexp.last_match(1))
        if recog_match
          info << ' ( '
          recog_match.each_pair do |k, v|
            next if k == 'matched'

            info << "#{k}=#{v} "
          end
          info << ')'
        end
      end

      print_status("SSH server version: #{ident}#{info}")
      report_service(host: target_host, port: rport, name: 'ssh', proto: 'tcp', info: ident)
      print_status(table.to_s)
    end
  rescue EOFError, Rex::ConnectionError => e
    vprint_error(e.message) # This may be a little noisy, but it is consistent
  rescue Timeout::Error
    vprint_warning("Timed out after #{timeout} seconds. Skipping.")
  end
end
