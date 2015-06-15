##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'recog'

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

  def peer
    "#{rhost}:#{rport}"
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
          ident, first_message = resp.split(/[\r\n]+/)
          if /^SSH-\d+\.\d+-(?<banner>.*)$/ =~ ident
            if recog_match = Recog::Nizer.match('ssh.banner', banner)
              info = recog_match.to_s
            else
              info = 'UNKNOWN'
              print_warning("#{peer} unknown SSH banner: #{banner}")
            end
            # Check to see if this is Kippo, which sends a premature
            # key init exchange right on top of the SSH version without
            # waiting for the required client identification string.
            if first_message && first_message.size >= 5
              extra = first_message.unpack("NCCA*") # sz, pad_sz, code, data
              if (extra.last.size + 2 == extra[0]) && extra[2] == 20
                info << " (Kippo Honeypot)"
              end
            end
            print_status("#{peer}, SSH server version: #{ident}")
            report_service(host: rhost, port: rport, name: 'ssh', proto: 'tcp', info: info)
          else
            vprint_warning("#{peer} was not SSH --"  \
                          " #{resp.size} bytes beginning with #{resp[0, 12]}")
          end
        else
          vprint_warning("#{peer} no response")
        end
      end
    rescue Timeout::Error
      vprint_warning("#{peer} timed out after #{timeout} seconds. Skipping.")
    ensure
      disconnect
    end
  end
end
