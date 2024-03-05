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
      'Description' => 'Detect SSH Version, and the server encryption',
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
        OptInt.new('TIMEOUT', [true, 'Timeout for the SSH probe', 30]),
        OptBool.new('EXTENDED_CHECKS', [true, 'Check for cryptographic issues', true])
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

  def perform_recog(ident)
    table = []
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

    return table if recog_info.empty?

    recog_info.each do |info|
      info = info.split(': ')
      table << [info[0], info[1..].join(': ')]
    end
    table
  end

  def check_host_key(server_data)
    table = []

    host_key_checks = {
      %w[
        ecdsa-sha2-nistp521 ecdsa-sha2-nistp384
        ecdsa-sha2-nistp256
      ] => ['https://github.com/net-ssh/net-ssh?tab=readme-ov-file#host-keys']
    }
    server_data[:host_key].each do |host_key|
      note = ''
      host_key_checks.each do |host_key_check, refs|
        host_key_check.each do |bad_key|
          next unless host_key.downcase == bad_key

          vprint_good("#{target_host} - Host Key Encryption #{host_key} uses a weak elliptic curve and should not be used.")
          report_vuln(
            host: target_host,
            port: rport,
            proto: 'tcp',
            name: name,
            info: "Module #{fullname} confirmed SSH Host Key Encryption #{host_key} is available, but should be deprecated",
            refs: refs
          )
          note = 'Weak elliptic curve'
        end
      end
      table << ['encryption.host_key', host_key, note]
    end
    table
  end

  def check_encryption(server_data)
    table = []

    encryption_checks = {
      'arcfour' => ['https://datatracker.ietf.org/doc/html/rfc8758#name-iana-considerations'],
      'arcfour128' => ['https://datatracker.ietf.org/doc/html/rfc8758#name-iana-considerations'],
      'arcfour256' => ['https://datatracker.ietf.org/doc/html/rfc8758#name-iana-considerations'],
      'aes256-cbc' => ['https://github.com/net-ssh/net-ssh?tab=readme-ov-file#encryption-algorithms-ciphers', 'CVE-2008-5161'],
      'aes192-cbc' => ['https://github.com/net-ssh/net-ssh?tab=readme-ov-file#encryption-algorithms-ciphers', 'CVE-2008-5161'],
      'aes128-cbc' => ['https://github.com/net-ssh/net-ssh?tab=readme-ov-file#encryption-algorithms-ciphers', 'CVE-2008-5161'],
      'rijndael-cbc@lysator.liu.se' => ['https://github.com/net-ssh/net-ssh?tab=readme-ov-file#encryption-algorithms-ciphers', 'CVE-2008-5161'],
      'blowfish-cbc' => ['https://github.com/net-ssh/net-ssh?tab=readme-ov-file#encryption-algorithms-ciphers', 'CVE-2008-5161'],
      'cast128-cbc' => ['https://github.com/net-ssh/net-ssh?tab=readme-ov-file#encryption-algorithms-ciphers', 'CVE-2008-5161'],
      '3des-cbc' => ['https://github.com/net-ssh/net-ssh?tab=readme-ov-file#encryption-algorithms-ciphers', 'CVE-2008-5161'],
      'idea-cbc' => ['https://github.com/net-ssh/net-ssh?tab=readme-ov-file#encryption-algorithms-ciphers', 'CVE-2008-5161'],
      'twofish-cbc' => ['https://github.com/net-ssh/net-ssh?tab=readme-ov-file#encryption-algorithms-ciphers', 'CVE-2008-5161'],
      'twofish128-cbc' => ['https://github.com/net-ssh/net-ssh?tab=readme-ov-file#encryption-algorithms-ciphers', 'CVE-2008-5161'],
      'twofish256-cbc' => ['https://github.com/net-ssh/net-ssh?tab=readme-ov-file#encryption-algorithms-ciphers', 'CVE-2008-5161'],
      'blowfish-ctr' => ['https://github.com/net-ssh/net-ssh?tab=readme-ov-file#encryption-algorithms-ciphers'],
      'cast128-ctr' => ['https://github.com/net-ssh/net-ssh?tab=readme-ov-file#encryption-algorithms-ciphers'],
      '3des-ctr' => ['https://github.com/net-ssh/net-ssh?tab=readme-ov-file#encryption-algorithms-ciphers'],
      'none' => ['https://github.com/net-ssh/net-ssh?tab=readme-ov-file#encryption-algorithms-ciphers']
    }

    server_data[:encryption_server].each do |encryption|
      note = ''
      encryption_checks.each do |bad_enc, refs|
        next unless encryption.downcase == bad_enc

        vprint_good("#{target_host} - Encryption #{encryption} is deprecated and should not be used.")
        report_vuln(
          host: target_host,
          port: rport,
          proto: 'tcp',
          name: name,
          info: "Module #{fullname} confirmed SSH Encryption #{encryption} is available, but should be deprecated",
          refs: refs
        )
        note = 'Deprecated'
      end
      table << ['encryption.encryption', encryption, note]
    end
    table
  end

  def check_kex(server_data)
    table = []
    kex_checks = {
      'gss-group1-sha1-*' => ['https://datatracker.ietf.org/doc/html/rfc8732#name-deprecated-algorithms'],
      'gss-group14-sha1-gss-gex-sha1-*' => ['https://datatracker.ietf.org/doc/html/rfc8732#name-deprecated-algorithms'],
      'gss-gex-sha1-*' => ['https://datatracker.ietf.org/doc/html/rfc8732#name-deprecated-algorithms'],
      'ecdsa-sha2-nistp521' => ['https://github.com/net-ssh/net-ssh?tab=readme-ov-file#key-exchange'],
      'ecdsa-sha2-nistp384' => ['https://github.com/net-ssh/net-ssh?tab=readme-ov-file#key-exchange'],
      'ecdsa-sha2-nistp256' => ['https://github.com/net-ssh/net-ssh?tab=readme-ov-file#key-exchange'],
      'diffie-hellman-group-exchange-sha1' => ['https://datatracker.ietf.org/doc/html/draft-ietf-curdle-ssh-kex-sha2-20#page-16'],
      'diffie-hellman-group1-sha1' => ['https://datatracker.ietf.org/doc/html/draft-ietf-curdle-ssh-kex-sha2-20#page-16'],
      'rsa1024-sha1' => ['https://datatracker.ietf.org/doc/html/draft-ietf-curdle-ssh-kex-sha2-20#page-16']
    }
    server_data[:kex].each do |kex|
      note = ''
      kex_checks.each do |bad_kex, refs|
        if bad_kex.ends_with? '*'
          next unless kex.downcase.start_with? bad_kex[0..-2]
        else
          next unless kex.downcase == bad_kex
        end

        vprint_good("#{target_host} - Key Exchange (kex) #{kex} is deprecated and should not be used.")
        report_vuln(
          host: target_host,
          port: rport,
          proto: 'tcp',
          name: name,
          info: "Module #{fullname} confirmed SSH Encryption #{kex} is available, but should be deprecated",
          refs: refs
        )
        note = 'Deprecated'
      end
      table << ['encryption.key_exchange', kex, note]
    end
    table
  end

  def check_hmac(server_data)
    table = []

    hmac_checks = {
      'hmac-sha2-512-96' => ['https://github.com/net-ssh/net-ssh?tab=readme-ov-file#message-authentication-code-algorithms'],
      'hmac-sha2-256-96' => ['https://github.com/net-ssh/net-ssh?tab=readme-ov-file#message-authentication-code-algorithms'],
      'hmac-sha1-96' => ['https://github.com/net-ssh/net-ssh?tab=readme-ov-file#message-authentication-code-algorithms'],
      'hmac-ripemd160' => ['https://github.com/net-ssh/net-ssh?tab=readme-ov-file#message-authentication-code-algorithms'],
      'hmac-md5' => ['https://github.com/net-ssh/net-ssh?tab=readme-ov-file#message-authentication-code-algorithms'],
      'hmac-md5-96' => ['https://github.com/net-ssh/net-ssh?tab=readme-ov-file#message-authentication-code-algorithms'],
      'none' => ['https://github.com/net-ssh/net-ssh?tab=readme-ov-file#message-authentication-code-algorithms']
    }

    server_data[:hmac_server].each do |hmac|
      note = ''
      hmac_checks.each do |bad_hmac, refs|
        next unless hmac.downcase == bad_hmac

        vprint_good("#{target_host} - HMAC #{hmac} is deprecated and should not be used.")
        report_vuln(
          host: target_host,
          port: rport,
          proto: 'tcp',
          name: name,
          info: "Module #{fullname} confirmed SSH HMAC #{hmac} is available, but should be deprecated",
          refs: refs
        )
        note = 'Deprecated'
      end
      table << ['encryption.hmac', hmac, note]
    end
    table
  end

  def run_host(target_host)
    ::Timeout.timeout(timeout) do
      transport = Net::SSH::Transport::Session.new(target_host, { port: rport })

      server_data = transport.algorithms.instance_variable_get(:@server_data)
      host_keys = transport.algorithms.session.instance_variable_get(:@host_keys).instance_variable_get(:@host_keys)
      host_keys.each do |host_key|
        print_status("#{target_host} - Key Fingerprint: #{host_key.ssh_type} #{Base64.strict_encode64(host_key.to_blob)}")
      end

      ident = transport.server_version.version

      print_status("#{target_host} - SSH server version: #{ident}")

      report_service(host: target_host, port: rport, name: 'ssh', proto: 'tcp', info: ident)

      return unless datastore['EXTENDED_CHECKS']

      table = Rex::Text::Table.new(
        'Header' => 'Server Information and Encryption',
        'Indent' => 2,
        'SortIndex' => 0,
        'Columns' => %w[Type Value Note]
      )

      # if these ever get expanded to have checks, they should be moved to their own function
      server_data[:language_server].each do |language|
        table << ['encryption.language', language, '']
      end

      # if these ever get expanded to have checks, they should be moved to their own function
      server_data[:compression_server].each do |compression|
        table << ['encryption.compression', compression, '']
      end

      table.rows.concat check_kex(server_data)

      table.rows.concat check_host_key(server_data)

      table.rows.concat check_hmac(server_data)

      table.rows.concat check_encryption(server_data)

      table.rows.concat perform_recog(ident)

      # XXX check for host key size?
      # h00die - not sure how to get that info from the library.
      # https://www.tenable.com/plugins/nessus/153954

      print_status("#{target_host} - #{table}")
    end
  rescue EOFError, Rex::ConnectionError => e
    vprint_error("#{target_host} - #{e.message}") # This may be a little noisy, but it is consistent
  rescue Timeout::Error
    vprint_warning("#{target_host} - Timed out after #{timeout} seconds. Skipping.")
  end
end
