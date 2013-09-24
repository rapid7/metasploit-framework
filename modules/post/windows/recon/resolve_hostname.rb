##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'
require 'rex'

class Metasploit3 < Msf::Post
  require 'msf/core/module/deprecated'
  include Msf::Module::Deprecated
  deprecated Date.new(2014, 03, 24), 'post/windows/recon/resolve_hosts'

  def initialize(info={})
    super( update_info( info,
        'Name'          => 'Windows Recon Resolve Hostname',
        'Description'   => %q{
            This module resolves a hostname to IP address via the victim,
            similar to the Unix 'dig' command. Since resolution happens over
            an established session from the perspective of the remote host,
            this module can be used to determine differences between external
            and internal resolution, especially for potentially high-value
            internal addresses of devices named 'mail' or 'www.'
          },
        'License'       => MSF_LICENSE,
        'Author'        => [ 'mubix' ],
        'Platform'      => [ 'win' ],
        'SessionTypes'  => [ 'meterpreter' ]
      ))

    register_options(
      [
        OptString.new('HOSTNAME', [false, 'Hostname to lookup', nil]),
        OptPath.new('HOSTFILE', [false, 'Line separated file with hostnames to resolve', nil]),
        OptBool.new('SAVEHOSTS', [true, 'Save resolved hosts to the database', true])
      ], self.class)
  end

  def resolve_hostname(hostname)
    begin
      vprint_status("Looking up IP for #{hostname}")
      result = client.net.resolve.resolve_host(hostname)
      if result[:ip].nil? or result[:ip].blank?
        print_error("Failed to resolve #{hostname}")
        return
      else
        hostip = result[:ip]
      end


      print_status("#{hostname} resolves to #{hostip}")

      if datastore['SAVEHOSTS']
        report_host({
          :host => hostip,
          :name => hostname
        })
      end

    rescue Rex::Post::Meterpreter::RequestError
      print_status('Windows 2000 and prior does not support getaddrinfo')
    end

  end

  def run
    if datastore['HOSTNAME']
      resolve_hostname(datastore['HOSTNAME'])
    end

    if datastore['HOSTFILE']
      ::File.open(datastore['HOSTFILE'], "rb").each_line do |hostname|
        if hostname.strip != ""
          resolve_hostname(hostname.strip)
        end
      end
    end
  end
end
