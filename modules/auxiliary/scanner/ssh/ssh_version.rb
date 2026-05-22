##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'recog'
require 'net/ssh/transport/session'

class MetasploitModule < Msf::Auxiliary
  include Msf::Auxiliary::Scanner
  include Msf::Exploit::Remote::SSH

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

  def report_weak_algo_vuln(vuln_name, algo_label, deprecated)
    return if deprecated.empty?

    report_vuln(
      host: target_host,
      port: rport,
      proto: 'tcp',
      sname: 'ssh',
      name: vuln_name,
      info: "Module #{fullname} confirmed deprecated SSH #{algo_label} algorithms: #{deprecated.map { |d| d[:name] }.join(', ')}",
      refs: deprecated.flat_map { |d| d[:refs] }.uniq,
      check_code: Msf::Exploit::CheckCode.Appears("Deprecated SSH #{algo_label} algorithms detected")
    )
  end

  def check_host_key_size(host_keys)
    table = []
    deprecated = []

    key_size_checks = {
      'ssh-rsa' => {
        min_bits: 2048,
        bits: ->(k) { k.n.num_bits },
        standard: 'NIST SP 800-131A',
        refs: ['https://csrc.nist.gov/publications/detail/sp/800-131a/rev-2/final']
      },
      'ssh-dss' => {
        min_bits: 2048,
        bits: ->(k) { k.p.num_bits },
        standard: 'NIST SP 800-131A',
        refs: ['https://csrc.nist.gov/publications/detail/sp/800-131a/rev-2/final']
      }
    }

    host_keys.each do |host_key|
      check = key_size_checks[host_key.ssh_type]
      next unless check

      bits = check[:bits].call(host_key)
      next if bits >= check[:min_bits]

      vprint_good("#{target_host} - #{host_key.ssh_type} host key is #{bits}-bit (weak, minimum #{check[:min_bits]}-bit per #{check[:standard]})")
      deprecated << { name: "#{host_key.ssh_type} (#{bits}-bit)", refs: check[:refs] }
      table << ['encryption.host_key', "#{host_key.ssh_type} (#{bits}-bit)", "Weak key size (min #{check[:min_bits]}-bit)"]
    end

    report_weak_algo_vuln('SSH Weak Host Key Size', 'Host Key Size', deprecated)
    table
  end

  def check_host_key(server_data)
    table = []
    deprecated = []

    host_key_checks = {
      'ecdsa-sha2-nistp521' => { note: 'Weak elliptic curve', refs: ['https://github.com/net-ssh/net-ssh?tab=readme-ov-file#host-keys'] },
      'ecdsa-sha2-nistp384' => { note: 'Weak elliptic curve', refs: ['https://github.com/net-ssh/net-ssh?tab=readme-ov-file#host-keys'] },
      'ecdsa-sha2-nistp256' => { note: 'Weak elliptic curve', refs: ['https://github.com/net-ssh/net-ssh?tab=readme-ov-file#host-keys'] },
      'ssh-dss' => { note: 'Deprecated SHA-1', refs: ['https://www.openssh.com/legacy.html'] }
    }

    server_data[:host_key].each do |host_key|
      note = ''
      host_key_checks.each do |bad_key, data|
        next unless host_key.downcase == bad_key

        vprint_good("#{target_host} - Host Key #{host_key} is deprecated and should not be used")
        deprecated << { name: host_key, refs: data[:refs] }
        note = data[:note].presence || 'Deprecated'
      end
      table << ['encryption.host_key', host_key, note]
    end

    report_weak_algo_vuln('SSH Weak Host Key Algorithm', 'Host Key', deprecated)
    table
  end

  def check_encryption(server_data)
    table = []
    deprecated = []

    encryption_checks = {
      'arcfour' => { note: 'RC4 stream cipher', refs: ['https://datatracker.ietf.org/doc/html/rfc8758#name-iana-considerations'] },
      'arcfour128' => { note: 'RC4 stream cipher', refs: ['https://datatracker.ietf.org/doc/html/rfc8758#name-iana-considerations'] },
      'arcfour256' => { note: 'RC4 stream cipher', refs: ['https://datatracker.ietf.org/doc/html/rfc8758#name-iana-considerations'] },
      'aes256-cbc' => { note: 'CBC padding oracle', refs: ['https://github.com/net-ssh/net-ssh?tab=readme-ov-file#encryption-algorithms-ciphers', 'CVE-2008-5161'] },
      'aes192-cbc' => { note: 'CBC padding oracle', refs: ['https://github.com/net-ssh/net-ssh?tab=readme-ov-file#encryption-algorithms-ciphers', 'CVE-2008-5161'] },
      'aes128-cbc' => { note: 'CBC padding oracle', refs: ['https://github.com/net-ssh/net-ssh?tab=readme-ov-file#encryption-algorithms-ciphers', 'CVE-2008-5161'] },
      'rijndael-cbc@lysator.liu.se' => { note: 'CBC padding oracle', refs: ['https://github.com/net-ssh/net-ssh?tab=readme-ov-file#encryption-algorithms-ciphers', 'CVE-2008-5161'] },
      'blowfish-cbc' => { note: 'CBC padding oracle', refs: ['https://github.com/net-ssh/net-ssh?tab=readme-ov-file#encryption-algorithms-ciphers', 'CVE-2008-5161'] },
      'cast128-cbc' => { note: 'CBC padding oracle', refs: ['https://github.com/net-ssh/net-ssh?tab=readme-ov-file#encryption-algorithms-ciphers', 'CVE-2008-5161'] },
      '3des-cbc' => { note: 'CBC padding oracle', refs: ['https://github.com/net-ssh/net-ssh?tab=readme-ov-file#encryption-algorithms-ciphers', 'CVE-2008-5161'] },
      'idea-cbc' => { note: 'CBC padding oracle', refs: ['https://github.com/net-ssh/net-ssh?tab=readme-ov-file#encryption-algorithms-ciphers', 'CVE-2008-5161'] },
      'twofish-cbc' => { note: 'CBC padding oracle', refs: ['https://github.com/net-ssh/net-ssh?tab=readme-ov-file#encryption-algorithms-ciphers', 'CVE-2008-5161'] },
      'twofish128-cbc' => { note: 'CBC padding oracle', refs: ['https://github.com/net-ssh/net-ssh?tab=readme-ov-file#encryption-algorithms-ciphers', 'CVE-2008-5161'] },
      'twofish256-cbc' => { note: 'CBC padding oracle', refs: ['https://github.com/net-ssh/net-ssh?tab=readme-ov-file#encryption-algorithms-ciphers', 'CVE-2008-5161'] },
      'blowfish-ctr' => { note: 'Removed from spec', refs: ['https://github.com/net-ssh/net-ssh?tab=readme-ov-file#encryption-algorithms-ciphers'] },
      'cast128-ctr' => { note: 'Removed from spec', refs: ['https://github.com/net-ssh/net-ssh?tab=readme-ov-file#encryption-algorithms-ciphers'] },
      '3des-ctr' => { note: 'Removed from spec', refs: ['https://github.com/net-ssh/net-ssh?tab=readme-ov-file#encryption-algorithms-ciphers'] },
      'none' => { note: 'No encryption', refs: ['https://github.com/net-ssh/net-ssh?tab=readme-ov-file#encryption-algorithms-ciphers'] }
    }

    server_data[:encryption_server].each do |encryption|
      note = ''
      encryption_checks.each do |bad_enc, data|
        next unless encryption.downcase == bad_enc

        vprint_good("#{target_host} - Encryption #{encryption} is deprecated and should not be used")
        deprecated << { name: encryption, refs: data[:refs] }
        note = data[:note].presence || 'Deprecated'
      end
      table << ['encryption.encryption', encryption, note]
    end

    report_weak_algo_vuln('SSH Weak Encryption Cipher', 'Encryption', deprecated)
    table
  end

  def check_kex(server_data)
    table = []
    deprecated = []

    kex_checks = {
      'gss-group1-sha1-*' => { note: 'SHA-1 weakness', refs: ['https://datatracker.ietf.org/doc/html/rfc8732#name-deprecated-algorithms'] },
      'gss-group14-sha1-*' => { note: 'SHA-1 weakness', refs: ['https://datatracker.ietf.org/doc/html/rfc8732#name-deprecated-algorithms'] },
      'gss-gex-sha1-*' => { note: 'SHA-1 weakness', refs: ['https://datatracker.ietf.org/doc/html/rfc8732#name-deprecated-algorithms'] },
      'diffie-hellman-group-exchange-sha1' => { note: 'SHA-1 weakness', refs: ['https://datatracker.ietf.org/doc/html/draft-ietf-curdle-ssh-kex-sha2-20#page-16'] },
      'diffie-hellman-group1-sha1' => { note: 'SHA-1 weakness', refs: ['https://datatracker.ietf.org/doc/html/draft-ietf-curdle-ssh-kex-sha2-20#page-16'] },
      'rsa1024-sha1' => { note: 'SHA-1 weakness', refs: ['https://datatracker.ietf.org/doc/html/draft-ietf-curdle-ssh-kex-sha2-20#page-16'] }
    }

    server_data[:kex].each do |kex|
      note = ''
      kex_checks.each do |bad_kex, data|
        if bad_kex.ends_with? '*'
          next unless kex.downcase.start_with? bad_kex[0..-2]
        else
          next unless kex.downcase == bad_kex
        end

        vprint_good("#{target_host} - Key EXchange (KEX) #{kex} is deprecated and should not be used")
        deprecated << { name: kex, refs: data[:refs] }
        note = data[:note].presence || 'Deprecated'
      end
      table << ['encryption.key_exchange', kex, note]
    end

    report_weak_algo_vuln('SSH Weak Key Exchange Algorithm', 'Key Exchange', deprecated)
    table
  end

  def check_hmac(server_data)
    table = []
    deprecated = []

    hmac_checks = {
      'hmac-sha2-512-96' => { note: 'Truncated HMAC', refs: ['https://github.com/net-ssh/net-ssh?tab=readme-ov-file#message-authentication-code-algorithms'] },
      'hmac-sha2-256-96' => { note: 'Truncated HMAC', refs: ['https://github.com/net-ssh/net-ssh?tab=readme-ov-file#message-authentication-code-algorithms'] },
      'hmac-sha1-96' => { note: 'Truncated HMAC', refs: ['https://github.com/net-ssh/net-ssh?tab=readme-ov-file#message-authentication-code-algorithms'] },
      'hmac-ripemd160' => { note: 'RIPEMD-160 weakness', refs: ['https://github.com/net-ssh/net-ssh?tab=readme-ov-file#message-authentication-code-algorithms'] },
      'hmac-md5' => { note: 'MD5 collision', refs: ['https://github.com/net-ssh/net-ssh?tab=readme-ov-file#message-authentication-code-algorithms'] },
      'hmac-md5-96' => { note: 'MD5 collision', refs: ['https://github.com/net-ssh/net-ssh?tab=readme-ov-file#message-authentication-code-algorithms'] },
      'none' => { note: 'No authentication', refs: ['https://github.com/net-ssh/net-ssh?tab=readme-ov-file#message-authentication-code-algorithms'] }
    }

    server_data[:hmac_server].each do |hmac|
      note = ''
      hmac_checks.each do |bad_hmac, data|
        next unless hmac.downcase == bad_hmac

        vprint_good("#{target_host} - HMAC #{hmac} is deprecated and should not be used")
        deprecated << { name: hmac, refs: data[:refs] }
        note = data[:note].presence || 'Deprecated'
      end
      table << ['encryption.hmac', hmac, note]
    end

    report_weak_algo_vuln('SSH Weak HMAC Algorithm', 'HMAC', deprecated)
    table
  end

  def run_host(target_host)
    ::Timeout.timeout(timeout) do
      transport = connect_ssh_transport(target_host, ssh_client_defaults.merge(port: rport))

      server_data = transport.algorithms.instance_variable_get(:@server_data)
      host_keys = transport.algorithms.session.instance_variable_get(:@host_keys).instance_variable_get(:@host_keys)
      host_keys.each do |host_key|
        print_status("#{target_host} - Key Fingerprint: #{host_key.ssh_type} #{Base64.strict_encode64(host_key.to_blob)}")
      end

      ident = transport.server_version.version

      print_status("#{target_host} - SSH banner: #{ident}")

      return unless datastore['EXTENDED_CHECKS']

      table = Rex::Text::Table.new(
        'Header' => 'SSH Server Details',
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

      table.rows.concat check_host_key_size(host_keys)

      table.rows.concat check_hmac(server_data)

      table.rows.concat check_encryption(server_data)

      table.rows.concat perform_recog(ident)

      print_status("#{target_host} - #{table}")

      flagged_rows = table.rows.reject { |r| r[2].to_s.empty? }
      if flagged_rows.any?
        category_labels = {
          'encryption.key_exchange' => 'KEX',
          'encryption.host_key' => 'Host Key',
          'encryption.hmac' => 'HMAC',
          'encryption.encryption' => 'Encryption'
        }
        breakdown = flagged_rows.group_by { |r| r[0] }.map do |type, rows|
          "#{rows.count} #{category_labels[type] || type}"
        end.join(', ')
        print_warning("#{target_host} - Found #{flagged_rows.count} deprecated/weak algorithm(s): #{breakdown}")
      end
    end
  rescue EOFError, Rex::ConnectionError => e
    vprint_error("#{target_host} - #{e.message}") # This may be a little noisy, but it is consistent
  rescue Timeout::Error
    vprint_warning("#{target_host} - Timed out after #{timeout} seconds. Skipping.")
  end
end
