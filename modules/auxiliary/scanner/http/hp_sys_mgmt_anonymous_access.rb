require 'msf/core'


class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report

  def initialize(info={})
    super(update_info(info,
      'Name'            => 'HP System Management Login Anonymous Access Scanner',
      'Description'     => %q{
This module checks to see if anonymous access is allowed for HP System Management Login
web interface. hp_sys_mgmt_exec exploit is dependent upon anonymous access. Anonymous access can also disclose server configuration and SNMP community vaules.
This was made into a scanner to be able to quickly test large networks. SSL is enabled by default.},
      'Author'          => [ 'g1ldedm1n1on(at)gmail.com' ],
      'License'         => MSF_LICENSE,
      'DefaultOptions' => { 'SSL' => TRUE }
   ))

    register_options(
  [
    Opt::RPORT(2381)
  ], self.class)
end

 def anonymous_access?
    res = send_request_raw({'uri' => '/'})
    res and res.body =~ /username = "hpsmh_anonymous"/
    false
  end


  def run_host(target_host)
  begin
      print_status("#{target_host} - Testing for Anonymous Access")
    res = send_request_cgi({
  'method' => 'POST',
  'uri' => '/',
  'vars_post' => {
  'redirecturl'         => '',
  'redirectquerystring'   => '',
  }
  })

   unless res
  vprint_error("#{target_host} - Failed to Connect")
  return :abort
    end
  rescue ::Rex::ConnectionError, Errno::ECONNREFUSED
  vprint_error("#{target_host} - Failed to responed")
  return :abort
end

#def run
  unless anonymous_access?
    vprint_error("#{target_host} - Server does not allow anonymous access")
 else
    print_good("#{target_host} - System allows anonymous access")
return
end
end
end
