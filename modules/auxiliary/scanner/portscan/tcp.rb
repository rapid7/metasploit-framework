##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##


require 'msf/core'

class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::Remote::Tcp

  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Scanner


  def initialize
    super(
      'Name'        => 'TCP Port Scanner',
      'Description' => 'Enumerate open TCP services',
      'Author'      => [ 'hdm', 'kris katterjohn' ],
      'License'     => MSF_LICENSE
    )

    register_options(
    [
      OptString.new('PORTS', [true, "Ports to scan (e.g. 22-25,80,110-900)", "1-10000"]),
      OptInt.new('TIMEOUT', [true, "The socket connect timeout in milliseconds", 1000]),
      OptInt.new('CONCURRENCY', [true, "The number of concurrent ports to check per host", 10]),
    ], self.class)

    deregister_options('RPORT')

  end


  def run_host(ip)

    timeout = datastore['TIMEOUT'].to_i

    ports = Rex::Socket.portspec_crack(datastore['PORTS'])

    if ports.empty?
      print_error("Error: No valid ports specified")
      return
    end

    while(ports.length > 0)
      t = []
      r = []
      begin
      1.upto(datastore['CONCURRENCY']) do
        this_port = ports.shift
        break if not this_port
        t << framework.threads.spawn("Module(#{self.refname})-#{ip}:#{this_port}", false, this_port) do |port|
          begin
            s = connect(false,
              {
                'RPORT' => port,
                'RHOST' => ip,
                'ConnectTimeout' => (timeout / 1000.0)
              }
            )
            print_status("#{ip}:#{port} - TCP OPEN")
            r << [ip,port,"open"]
          rescue ::Rex::ConnectionRefused
            vprint_status("#{ip}:#{port} - TCP closed")
            r << [ip,port,"closed"]
          rescue ::Rex::ConnectionError, ::IOError, ::Timeout::Error
          rescue ::Rex::Post::Meterpreter::RequestError
          rescue ::Interrupt
            raise $!
          rescue ::Exception => e
            print_error("#{ip}:#{port} exception #{e.class} #{e} #{e.backtrace}")
          ensure
            disconnect(s) rescue nil
          end
        end
      end
      t.each {|x| x.join }

      rescue ::Timeout::Error
      ensure
        t.each {|x| x.kill rescue nil }
      end

      r.each do |res|
        report_service(:host => res[0], :port => res[1], :state => res[2])
      end
    end
  end

end
