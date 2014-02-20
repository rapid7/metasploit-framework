##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##


require 'msf/core'


class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::Remote::DB2
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report

  def initialize
    super(
      'Name'           => 'DB2 Probe Utility',
      'Description'    => 'This module queries a DB2 instance information.',
      'Author'         => ['todb'],
      'License'        => MSF_LICENSE
    )
    register_options(
      [
        OptInt.new('TIMEOUT', [true, 'Timeout for the DB2 probe', 5])
    ], self.class)

    deregister_options('USERNAME' , 'PASSWORD')
  end

  def to
    return 5 if datastore['TIMEOUT'].to_i.zero?
    datastore['TIMEOUT'].to_i
  end

  def run_host(ip)
    begin

      info = db2_probe(to)
      if info[:excsatrd]
        inst,plat,ver,pta = info[:instance_name],info[:platform],info[:version],info[:plaintext_auth]
        report_info = "Platform: #{plat}, Version: #{ver}, Instance: #{inst}, Plain-Authentication: #{pta ? "OK" : "NO"}"
        print_status("#{ip}:#{rport} DB2 - #{report_info}")
        report_service(
          :host => rhost,
          :port => rport,
          :name => "db2",
          :info => report_info
        )
      end
      disconnect

    rescue ::Rex::ConnectionRefused
      vprint_error("#{rhost}:#{rport} : Cannot connect to host")
      return :done
    rescue ::Rex::ConnectionError
      vprint_error("#{rhost}:#{rport} : Unable to attempt probe")
      return :done
    rescue ::Rex::Proto::DRDA::RespError => e
      vprint_error("#{rhost}:#{rport} : Error in connecting to DB2 instance: #{e}")
      return :error
    end
  end
end
