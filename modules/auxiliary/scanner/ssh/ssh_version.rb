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
        ['URL', 'https://github.com/net-ssh/net-ssh?tab=readme-ov-file#supported-algorithms'], # a bunch of diff removed things from the ruby lib
        ['CVE', '2008-5161'] # CBC modes
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
      print_status("#{target_host} - Key Fingerprint: #{host_keys[0].fingerprint}") if host_keys.length.positive?

      ident = transport.server_version.version

      table = Rex::Text::Table.new(
        'Header' => 'Server Encryption',
        'Indent' => 2,
        'SortIndex' => 0,
        'Columns' => %w[Type Value]
      )

      server_data[:language_server].each do |language|
        table << ['Language', language]
      end

      server_data[:compression_server].each do |compression|
        table << ['Compression', compression]
      end

      encryption_checks = {
        %w[
          arcfour arcfour128
          arcfour256
        ] => ['https://datatracker.ietf.org/doc/html/rfc8758#name-iana-considerations'],
        %w[
          aes256-cbc aes192-cbc aes128-cbc rijndael-cbc@lysator.liu.se blowfish-cbc cast128-cbc 3des-cbc idea-cbc
          twofish-cbc twofish128-cbc twofish256-cbc
        ] => [
          'https://github.com/net-ssh/net-ssh?tab=readme-ov-file#encryption-algorithms-ciphers', 'CVE-2008-5161'
        ],
        %w[
          blowfish-ctr cast128-ctr 3des-ctr
          none
        ] => ['https://github.com/net-ssh/net-ssh?tab=readme-ov-file#encryption-algorithms-ciphers']
      }

      server_data[:encryption_server].each do |encryption|
        encryption_checks.each do |encryptions, refs|
          encryptions.each do |bad_enc|
            next unless encryption.downcase.start_with? bad_enc

            print_good("#{target_host} - Encryption #{encryption} is deprecated and should not be used.")
            report_vuln(
              host: target_host,
              port: rport,
              proto: 'tcp',
              name: name,
              info: "Module #{fullname} confirmed SSH Encryption #{encryption} is available, but should be deprecated",
              refs: refs
            )
          end
        end
        table << ['Encryption', encryption]
      end

      hmac_checks = {
        %w[
          hmac-sha2-512-96 hmac-sha2-256-96 hmac-sha1-96 hmac-ripemd160 hmac-md5 hmac-md5-96
          none
        ] => ['https://github.com/net-ssh/net-ssh?tab=readme-ov-file#message-authentication-code-algorithms']
      }

      server_data[:hmac_server].each do |hmac|
        hmac_checks.each do |hmacs, refs|
          hmacs.each do |bad_hmac|
            next unless hmac.downcase.start_with? bad_hmac

            print_good("#{target_host} - HMAC #{hmac} is deprecated and should not be used.")
            report_vuln(
              host: target_host,
              port: rport,
              proto: 'tcp',
              name: name,
              info: "Module #{fullname} confirmed SSH HMAC #{hmac} is available, but should be deprecated",
              refs: refs
            )
          end
        end
        table << ['HMAC', hmac]
      end

      host_key_checks = {
        %w[
          ecdsa-sha2-nistp521 ecdsa-sha2-nistp384
          ecdsa-sha2-nistp256
        ] => ['https://github.com/net-ssh/net-ssh?tab=readme-ov-file#host-keys']
      }
      server_data[:host_key].each do |host_key|
        host_key_checks.each do |host_key_check, refs|
          host_key_check.each do |bad_key|
            next unless host_key.downcase.start_with? bad_key

            print_good("#{target_host} - Host Key Encryption #{host_key} uses a weak elliptic curve and should not be used.")
            report_vuln(
              host: target_host,
              port: rport,
              proto: 'tcp',
              name: name,
              info: "Module #{fullname} confirmed SSH Host Key Encryption #{host_key} is available, but should be deprecated",
              refs: refs
            )
          end
        end
        table << ['Host Key', host_key]
      end

      kex_checks = {
        %w[gss-group1-sha1- gss-group14-sha1-gss-gex-sha1-] => ['https://datatracker.ietf.org/doc/html/rfc8732#name-deprecated-algorithms'],
        %w[
          ecdsa-sha2-nistp521 ecdsa-sha2-nistp384
          ecdsa-sha2-nistp256
        ] => ['https://github.com/net-ssh/net-ssh?tab=readme-ov-file#key-exchange'],
        %w[
          diffie-hellman-group-exchange-sha1 diffie-hellman-group1-sha1
          rsa1024-sha1
        ] => ['https://datatracker.ietf.org/doc/html/draft-ietf-curdle-ssh-kex-sha2-20#page-16']
      }
      server_data[:kex].each do |kex|
        kex_checks.each do |kexs, refs|
          kexs.each do |bad_kex|
            next unless kex.downcase.start_with? bad_kex

            print_good("#{target_host} - Key Exchange (kex) #{kex} is deprecated and should not be used.")
            report_vuln(
              host: target_host,
              port: rport,
              proto: 'tcp',
              name: name,
              info: "Module #{fullname} confirmed SSH Encryption #{kex} is available, but should be deprecated",
              refs: refs
            )
          end
        end
        table << ['Key Exchange (kex)', kex]
      end

      # XXX check for host key size?
      # h00die - not sure how to get that info from the library.
      # https://www.tenable.com/plugins/nessus/153954

      # Try to match with Recog and show the relevant fields to the user
      recog_info = []
      if /^SSH-\d+\.\d+-(.*)$/ =~ ident
        recog_match = Recog::Nizer.match('ssh.banner', ::Regexp.last_match(1))
        if recog_match
          recog_match.each_pair do |k, v|
            next if k == 'matched'

            recog_info << "#{k}: #{v}"
          end
        end
      end

      if !recog_info.empty?
        recog_info = "\n\t#{recog_info.join("\n\t")}"
      else
        recog_info = ''
      end
      print_status("#{target_host} - SSH server version: #{ident}#{recog_info}")
      report_service(host: target_host, port: rport, name: 'ssh', proto: 'tcp', info: ident)
      print_status("#{target_host} - #{table}")
    end
  rescue EOFError, Rex::ConnectionError => e
    vprint_error("#{target_host} - #{e.message}") # This may be a little noisy, but it is consistent
  rescue Timeout::Error
    vprint_warning("#{target_host} - Timed out after #{timeout} seconds. Skipping.")
  end
end
