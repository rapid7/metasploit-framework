##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'


class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::Remote::Tcp
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report

  def initialize
    super(
      'Name'        => 'SSH Version Scanner',
      'Description' => 'Detect SSH Version.',
      'References'  =>
        [
          [ 'URL', 'http://en.wikipedia.org/wiki/SecureShell' ],
        ],
      'Author'      => [ 'Daniel van Eeden <metasploit[at]myname.nl>' ],
      'License'     => MSF_LICENSE
    )

    register_options(
    [
      Opt::RPORT(22),
      OptInt.new('TIMEOUT', [true, 'Timeout for the SSH probe', 30])
    ], self.class)
  end

  def to
    return 30 if datastore['TIMEOUT'].to_i.zero?
    datastore['TIMEOUT'].to_i
  end

  def run_host(target_host)
    begin
      ::Timeout.timeout(to) do

        connect

        resp = sock.get_once(-1, 5)

        if (resp and resp =~ /SSH/)
          ver,msg = (resp.split(/[\r\n]+/))
          # Check to see if this is Kippo, which sends a premature
          # key init exchange right on top of the SSH version without
          # waiting for the required client identification string.
          if msg and msg.size >= 5
            extra = msg.unpack("NCCA*") # sz, pad_sz, code, data
            if (extra.last.size+2 == extra[0]) and extra[2] == 20
              ver << " (Kippo Honeypot)"
            end
          end
          print_status("#{target_host}:#{rport}, SSH server version: #{ver}")
          report_service(:host => rhost, :port => rport, :name => "ssh", :proto => "tcp", :info => ver)
        else
          print_error("#{target_host}:#{rport}, SSH server version detection failed!")
        end

        disconnect
      end

    rescue Timeout::Error
      print_error("#{target_host}:#{rport}, Server timed out after #{to} seconds. Skipping.")
    end
  end
end
