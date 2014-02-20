##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'rex'

class Metasploit3 < Msf::Post

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

    if client.platform =~ /^x64/
      size = 64
      addrinfoinmem = 32
    else
      size = 32
      addrinfoinmem = 24
    end

    begin
      vprint_status("Looking up IP for #{hostname}")
      result = client.railgun.ws2_32.getaddrinfo(hostname, nil, nil, 4 )
      if result['GetLastError'] == 11001
        print_error("Failed to resolve #{hostname}")
        return
      end
      addrinfo = client.railgun.memread( result['ppResult'], size )
      ai_addr_pointer = addrinfo[addrinfoinmem,4].unpack('L').first
      sockaddr = client.railgun.memread( ai_addr_pointer, size/2 )
      ip = sockaddr[4,4].unpack('N').first
      hostip = Rex::Socket.addr_itoa(ip)
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
