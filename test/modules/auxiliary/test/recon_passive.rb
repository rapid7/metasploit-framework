##
# $Id$
##

##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/framework/
##


require 'msf/core'


class Metasploit3 < Msf::Auxiliary

  include Msf::Auxiliary::Report
  include Msf::Exploit::Remote::Tcp

  def initialize
    super(
      'Name'        => 'Simple Recon Module Tester',
      'Version'     => '$Revision$',
      'Description' => 'Simple Recon Module Tester',
      'Author'      => 'hdm',
      'License'     => MSF_LICENSE,
      'Actions'     =>
        [
          ['Continuous Port Sweep']
        ],
      'PassiveActions' =>
        [
          'Continuous Port Sweep'
        ]
    )

    register_options(
      [
        Opt::RHOST,
        Opt::RPORT,
      ], self.class)

  end

  def run
    print_status("Running the simple recon module with action #{action.name}")

    case action.name
    when 'Continuous Port Sweep'
      while (true)
        1.upto(65535) do |port|
          datastore['RPORT'] = port
          prober()
        end
      end
    end
  end

  def prober
    begin
      connect
      disconnect
      report_host(:host => datastore['RHOST'])
      report_service(
        :host  => datastore['RHOST'],
        :port  => datastore['RPORT'],
        :proto => 'tcp'
      )
    rescue ::Exception => e
      case e.to_s
      when /connection was refused/
        report_host(:host => datastore['RHOST'])
      else
        print_status(e.to_s)
      end
    end
  end

end
