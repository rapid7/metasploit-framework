##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'net/ssh'
require 'rex/socket/ssh_factory'


class MetasploitModule < Msf::Auxiliary



  include Msf::Auxiliary::Scanner

  def initialize
    super(
      'Name'        => 'SSH Proxy Test',
      'Description' => %q{
        This module will test ssh logins on a range of machines and
        report successful logins.  If you have loaded a database plugin
        and connected to a database this module will record successful
        logins and hosts so you can track your access.
      },
      'Author'      => ['todb'],
      'References'     =>
        [
          [ 'CVE', '1999-0502'] # Weak password
        ],
      'License'     => MSF_LICENSE
    )

    register_options(
      [
        Opt::RPORT(22)
      ], self.class
    )

    register_advanced_options(
      [
        Opt::Proxies,
        OptBool.new('SSH_DEBUG', [ false, 'Enable SSH debugging output (Extreme verbosity!)', false]),
        OptInt.new('SSH_TIMEOUT', [ false, 'Specify the maximum time to negotiate a SSH session', 30])
      ]
    )

  end



  def run_host(ip)
    factory = Rex::Socket::SSHFactory.new(framework,self, datastore['Proxies'])
    # socket = factory.open(ip,datastore['RPORT'])

  end


end
