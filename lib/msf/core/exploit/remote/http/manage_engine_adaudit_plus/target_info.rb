# -*- coding: binary -*-

module Msf::Exploit::Remote::HTTP::ManageEngineAdauditPlus::TargetInfo
  include Msf::Exploit::Remote::HttpClient
  include Msf::Exploit::Remote::HTTP::ManageEngineAdauditPlus::StatusCodes
  include Msf::Exploit::Remote::HTTP::ManageEngineAdauditPlus::URIs

  # Check that a target is likely running ManageEngine ADAudit Plus
  #
  # @return [Hash] Hash containing a `status` key, which is used to hold a
  #   status value as an Integer value, a `message` key, which is used
  #   to hold a message associated with the status value as a String,
  #   and an optional 'server_response' key, which is used to hold the
  #   response body (String) received from the server.
  def adaudit_plus_target_check
    res = send_request_cgi({
      'uri' => normalize_uri(target_uri.path),
      'method' => 'GET'
    })

    unless res
      return {
        'status' => adaudit_plus_status::CONNECTION_FAILED,
        'message' => 'Connection failed.'
      }
    end

    if res.code == 200 && res.body =~ /<title>ADAudit Plus/
      return {
        'status' => adaudit_plus_status::SUCCESS,
        'message' => 'The target appears to be MangeEngine ADAudit Plus',
        'server_response' => res.body
      }
    end

    {
      'status' => adaudit_plus_status::UNEXPECTED_REPLY,
      'message' => 'The target does not appear to be MangeEngine ADAudit Plus',
    }
  end

  # Extract the configured aliases for the configured Active Directory
  # domains from a HTTP response body.
  #
  # @param res_body [String] HTTP response body obtained via a GET request to the ADAudit Plus base path
  # @return [Hash] Hash containing a `status` key, which is used to hold a
  #   status value as an Integer value, a `message` key, which is used
  #   to hold a message associated with the status value as a String,
  #   and a 'domain_aliases' key, which holds an Array of Strings for
  #   the configured domain aliases, or an empty Array if no domain
  #   aliases were found.
  def adaudit_plus_grab_domain_aliases(res_body)
    doc = ::Nokogiri::HTML(res_body)
    css_dom_name = doc.css('select#domainName')&.first
    domain_aliases = []

    no_domains_response = {
      'status' => adaudit_plus_status::NO_DOMAINS,
      'message' => 'No configured Active Directory domains were found.',
      'domain_aliases' => domain_aliases
    }

    return no_domains_response if css_dom_name.blank?

    css_configured_domains = css_dom_name.css('option')
    return no_domains_response if css_configured_domains.blank?

    css_configured_domains.each do |domain|
      next unless domain&.keys&.include?('value')
      value = domain['value']
      domain_aliases << value
    end

    return no_domains_response if domain_aliases.empty?

    {
      'status' => adaudit_plus_status::SUCCESS,
      'message' => "Identified #{domain_aliases.length} configured authentication domain(s): #{domain_aliases.join(', ')}",
      'domain_aliases' => domain_aliases
    }
  end

  # Performs an API call to obtain the configured domains. The adapcsrf
  # cookie obtained from this request is necessary to perform
  # further authenticated actions.
  #
  # @param adapcsrf_cookie [String] A valid adapcsrf_cookie obtained via a successful login action
  # @param only_get_cookie [Boolean] If this is enabled, the method will only try to obtain an
  #   'adapcsrf' cookie that is required to perform API calls.
  # @return [Hash] Hash containing a `status` key, which is used to hold a
  #   status value as an Integer value, an optional `message` key, which is
  #   used to hold a message associated with the status value as a String,
  #   an optional `adapcsrf_cookie` key which maps to a String containing the
  #   adapcsrf cookie to be used for authentication purposes, and an
  #   optional `configured_domains` key which maps to an Array of Strings,
  #   each containing a domain name that has been configured to be used by
  #   the ManageEngine ADAudit Plus target.
  def adaudit_plus_grab_configured_domains(adapcsrf_cookie, only_get_cookie = false)
    vprint_status('Attempting to obtain the list of configured domains...') unless only_get_cookie

    res = send_request_cgi({
      'uri' => adaudit_plus_configured_domains_uri,
      'method' => 'POST',
      'keep_cookies' => true,
      'vars_post' => {
        'JSONString' => '{"checkGDPR":true}',
        'adapcsrf' => adapcsrf_cookie.to_s
      }
    })

    if only_get_cookie
      purpose = 'obtain the adapcsrf cookie required to perform API calls'
    else
      purpose = 'obtain the list of configured domains'
    end

    unless res
      return {
        'status' => adaudit_plus_status::CONNECTION_FAILED,
        'message' => "Connection failed while attempting to #{purpose}."
      }
    end

    # if we didn't get an expected response, we should always return since we won't be able to return the domains and/or a valid cookie
    unless res.code == 200 && res.body&.include?('domainFullList')
      return {
        'status' => adaudit_plus_status::UNEXPECTED_REPLY,
        'message' => "Unexpected reply while attempting to #{purpose}."
      }
    end

    # try to obtain the adapcsrf cookie
    adapcsrf_cookie = cookie_jar.cookies.select { |k| k.name == 'adapcsrf' }&.first
    got_cookie = adapcsrf_cookie && adapcsrf_cookie.value.present? ? true : false

    # if we have no valid cookie there is no point in continuing
    unless got_cookie
      return {
        'status' => adaudit_plus_status::NO_ACCESS,
        'message' => 'Failed to obtain the adapcsrf cookie required to perform API calls'
      }
    end

    # if we only wanted to obtain the cookie, we can return here
    if only_get_cookie
      return {
        'status' => adaudit_plus_status::SUCCESS,
        'message' => 'Obtained the adapcsrf cookie required to perform API calls!',
        'adapcsrf_cookie' => adapcsrf_cookie.value
      }
    end

    # if we are here, we want to obtain the configured domains as well as the cookie
    configured_domains = []
    begin
      domain_info = JSON.parse(res.body)
      if domain_info && domain_info.include?('domainFullList') && !domain_info['domainFullList'].empty?
        domain_full_list = domain_info['domainFullList']
        domain_full_list.each do |domain|
          next unless domain.is_a?(Hash) && domain.key?('name')

          domain_name = domain['name']
          next if domain_name.empty?

          configured_domains << domain_name
        end
      else
        print_error('Failed to identify any configured domains.')
      end
    rescue JSON::ParserError => e
      print_error('Failed to identify any configured domains - The server response did not contain valid JSON.')
      print_error("Error was: #{e.message}")
    end

    if configured_domains.empty?
      return {
        'status' => adaudit_plus_status::NO_DOMAINS,
        'message' => 'Failed to obtain the list of configured domains.',
        'adapcsrf_cookie' => adapcsrf_cookie.value
      }
    end

    print_status("Found #{configured_domains.length} configured domain(s): #{configured_domains.join(', ')}")
    {
      'status' => adaudit_plus_status::SUCCESS,
      'message' => 'Obtained the adapcsrf cookie required to perform API calls along with the configured domains!',
      'adapcsrf_cookie' => adapcsrf_cookie.value,
      'configured_domains' => configured_domains
    }
  end

  # Check the build number for the ADAudit Plus installation
  #
  # @param adapcsrf_cookie [String] A valid ADAP CSRF cookie for API calls.
  # @see adaudit_plus_login The function which can be called to obtain a
  #   valid CSRF cookie that can be used by this code.
  # @return [Hash] Hash containing a `status` key, which is used to hold a
  #   status value as an Integer value, a `message` key, which is used
  #   to hold a message associated with the status value as a String,
  #   and an optional 'build_version' key, which is used to hold an object
  #   of type Rex::Version if the build number was successfully obtained.
  def adaudit_plus_grab_build(adapcsrf_cookie)
    vprint_status('Attempting to obtain the ADAudit Plus build number')

    res = send_request_cgi({
      'uri' => adaudit_plus_license_details_uri,
      'method' => 'POST',
      'keep_cookies' => true,
      'vars_post' => { 'adapcsrf' => adapcsrf_cookie.to_s }
    })

    unless res
      return {
        'status' => adaudit_plus_status::CONNECTION_FAILED,
        'message' => 'Connection failed while attempting to obtain the build number.'
      }
    end

    unless res.code == 200
      return {
        'status' => adaudit_plus_status::UNEXPECTED_REPLY,
        'message' => "Received unexpected HTTP response #{res.code} when attempting to obtain the build number."
      }
    end

    build = res.body&.scan(/"buildNumber":"(\s*\d{4}\s*)",/)&.flatten&.first
    if build.blank?
      return {
        'status' => adaudit_plus_status::NO_BUILD_NUMBER,
        'message' => 'No build number was obtained.'
      }
    end

    unless build.strip =~ /^\d{4}$/
      return {
        'status' => adaudit_plus_status::UNEXPECTED_REPLY,
        'message' => "Received an invalid build number: #{build}"
      }
    end

    {
      'status' => adaudit_plus_status::SUCCESS,
      'message' => "The target is ADAudit Plus #{build}",
      'build_version' => Rex::Version.new(build)
    }
  end

  # Check if the GPOWatcherData endpoint is available
  #
  # @return [Integer] Status code
  def gpo_watcher_data_check
    res = send_request_cgi({
      'uri' => adaudit_plus_gpo_watcher_data_uri,
      'method' => 'POST'
    })

    return adaudit_plus_status::CONNECTION_FAILED unless res
    return adaudit_plus_status::NO_ACCESS unless res.code == 200

    adaudit_plus_status::SUCCESS
  end
end
