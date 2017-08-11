##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'recog'

class MetasploitModule < Msf::Auxiliary
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

        if ! resp
          vprint_warning("No response")
          return
        end

        ident, first_message = resp.split(/[\r\n]+/)
        info = ""

        if /^SSH-\d+\.\d+-(.*)$/ !~ ident
          vprint_warning("Was not SSH -- #{resp.size} bytes beginning with #{resp[0, 12]}")
          return
        end

        banner = $1

        # Try to match with Recog and show the relevant fields to the user
        recog_match = Recog::Nizer.match('ssh.banner', banner)
        if recog_match
          info << " ( "
          recog_match.each_pair do |k,v|
            next if k == 'matched'
            info << "#{k}=#{v} "
          end
          info << ")"
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

        print_good("SSH server version: #{ident}#{info}")
        report_service(host: rhost, port: rport, name: 'ssh', proto: 'tcp', info: ident)
      end
    rescue Timeout::Error
      vprint_warning("Timed out after #{timeout} seconds. Skipping.")
    ensure
      disconnect
    end
  end
end
