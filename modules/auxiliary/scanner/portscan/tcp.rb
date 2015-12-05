##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
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
      OptInt.new('DELAY', [true, "The delay between connections, per thread, in milliseconds", 0]),
      OptInt.new('JITTER', [true, "The delay jitter factor (maximum value by which to +/- DELAY).", 0]),
    ], self.class)

    deregister_options('RPORT')

  end


def add_delay_jitter(_delay, _jitter)
  # Introduce the delay
  delay_value = _delay.to_i
  original_value = _delay.to_i
  jitter_value = _jitter.to_i
  
  # Retrieve the jitter value and delay value 
  # Delay = number of milliseconds to wait between each request
  # Jitter = percentage modifier. For example:
  # Delay is 1000ms (i.e. 1 second), Jitter is 50.
  # 50/100 = 0.5; 0.5*1000 = 500. Therefore, the per-request
  # delay will be 1000 +/- a maximum of 500ms. 
  if delay_value>0
    if jitter_value>0
       rnd = Random.new
       if (rnd.rand(2)==0)
          delay_value += rnd.rand(jitter_value)
       else
          delay_value -= rnd.rand(jitter_value)
       end 
       if delay_value<0
          delay_value = 0 
       end
    end 
    final_delay = delay_value.to_f/1000.0
    vprint_status("Delaying for #{final_delay} second(s) (#{original_value}ms +/- #{jitter_value}ms)")
    sleep final_delay
  end 
end

  def run_host(ip)

    timeout = datastore['TIMEOUT'].to_i

    ports = Rex::Socket.portspec_crack(datastore['PORTS'])

    if ports.empty?
      raise Msf::OptionValidateError.new(['PORTS'])
    end

    jitter_value = datastore['JITTER'].to_i
    if jitter_value<0 
      raise Msf::OptionValidateError.new(['JITTER'])
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

            add_delay_jitter(datastore['DELAY'],jitter_value)
      #      add_delay_jitter(datastore['DELAY'].to_i,jitter_value)
#            # Introduce the delay
#            delay_value = datastore['DELAY'].to_i
#            delay_proportion = jitter_value * (delay_value/100)
#
#            # Retrieve the jitter value and delay value 
#            # Delay = number of milliseconds to wait between each request
#            # Jitter = percentage modifier. For example:
#            # Delay is 1000ms (i.e. 1 second), Jitter is 50.
#            # 50/100 = 0.5; 0.5*1000 = 500. Therefore, the per-request
#            # delay will be 1000 +/- a maximum of 500ms. 
#            if delay_value>0
#                if delay_proportion>0
#                    rnd = Random.new
#                    delay_modifier = rnd.rand(delay_proportion)
#                    if (rnd.rand(2)==0)
#                        delay_value += delay_modifier
#                    else
#                        delay_value -= delay_modifier
#                    end
#                end
#                final_delay = delay_value.to_f/1000.0
#                vprint_status("Delaying for #{final_delay}s")
#                sleep final_delay
#            end

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
