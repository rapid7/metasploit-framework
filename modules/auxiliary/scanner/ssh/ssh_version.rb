##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary
  include Msf::Exploit::Remote::Tcp
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report

  # the default timeout (in seconds) to wait, in total, for both a successful
  # connection to a given endpoint and for the initial protocol response
  # from the supposed SSH endpoint to be returned
  DEFAULT_TIMEOUT = 30

  def initialize
    super(
      'Name'        => 'SSH Version Scanner',
      'Description' => 'Detect SSH Version.',
      'References'  =>
        [
          [ 'URL', 'http://en.wikipedia.org/wiki/SecureShell' ]
        ],
      'Author'      => [ 'Daniel van Eeden <metasploit[at]myname.nl>' ],
      'License'     => MSF_LICENSE
    )

    register_options(
      [
        Opt::RPORT(22),
        OptInt.new('TIMEOUT', [true, 'Timeout for the SSH probe', DEFAULT_TIMEOUT])
      ],
      self.class
    )
  end

  def timeout
    datastore['TIMEOUT'] <= 0 ? DEFAULT_TIMEOUT : datastore['TIMEOUT']
  end

  def run_host(target_host)
    begin
      ::Timeout.timeout(timeout) do
        connect

        resp = sock.get_once(-1, timeout)

        if resp
          if resp =~ /^SSH/
            ver, msg = resp.split(/[\r\n]+/)
            # Check to see if this is Kippo, which sends a premature
            # key init exchange right on top of the SSH version without
            # waiting for the required client identification string.
            if msg && msg.size >= 5
              extra = msg.unpack("NCCA*") # sz, pad_sz, code, data
              if (extra.last.size + 2 == extra[0]) && extra[2] == 20
                ver << " (Kippo Honeypot)"
              end
            end
            print_status("#{target_host}:#{rport}, SSH server version: #{ver}")
            report_service(host: rhost, port: rport, name: 'ssh', proto: 'tcp', info: ver)
          else
            vprint_warning("#{target_host}:#{rport} was not SSH --"  \
                          " #{resp.size} bytes beginning with #{resp[0, 12]}")
          end
        else
          vprint_warning("#{target_host}:#{rport} no response")
        end
      end
    rescue Timeout::Error
      vprint_warning("#{target_host}:#{rport} timed out after #{timeout} seconds. Skipping.")
    ensure
      disconnect
    end
  end
end
