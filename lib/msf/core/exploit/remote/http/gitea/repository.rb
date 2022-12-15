# -*- coding: binary -*-

module Msf::Exploit::Remote::HTTP::Gitea::Repository
  # performs a gitea repository creation
  #
  # @param name [String] Repository name
  # @param timeout [Integer] The maximum number of seconds to wait before the
  #   request times out
  # @return [uid,nil] the repository uid as a single string on successful
  #   creation, nil or raise RepositoryError and CsrfError otherwise
  def gitea_create_repo(name, timeout = 20)
    res = send_request_cgi({
      'uri' => gitea_url_repo_create,
      'keep_cookies' => true
    }, timeout)
    return nil unless res

    uid = gitea_get_repo_uid(res)
    raise Msf::Exploit::Remote::HTTP::Gitea::Error::RepositoryError.new('Unable to get repo uid') unless uid

    csrf = gitea_get_csrf(res)
    raise Msf::Exploit::Remote::HTTP::Gitea::Error::CsrfError.new unless csrf

    res = send_request_cgi(
      'method' => 'POST',
      'uri' => gitea_url_repo_create,
      'vars_post' => gitea_helper_repo_create_post_data(name, uid, csrf),
      'keep_cookies' => true
    )
    raise Msf::Exploit::Remote::HTTP::Gitea::Error::RepositoryError.new('Unable to create repo') if res&.code != 302
    return uid
  end

  # performs a gitea repository migration
  #
  # @param name [String] Repository name
  # @param name [String] Repository uid
  # @param timeout [Integer] The maximum number of seconds to wait before the
  #   request times out
  # @return [Rex::Proto::Http::Response, MigrationError] the HTTP response
  #   object on successful migration, raise MigrationError otherwise
  def gitea_migrate_repo(name, uid, url, token, timeout = 20)
    res = send_request_cgi({
      'uri' => gitea_url_repo_migrate,
      'keep_cookies' => true
    }, timeout)
    return nil unless res

    uri = gitea_get_service_type_uri(res)
    raise Msf::Exploit::Remote::HTTP::Gitea::Error::WebError.new('Unable to get service type uri') unless uri

    service = Rack::Utils.parse_query(URI.parse(uri).query)['service_type']
    res = send_request_cgi(
      'uri' => normalize_uri(target_uri.path, uri),
      'keep_cookies' => true
    )
    csrf = gitea_get_csrf(res)
    raise Msf::Exploit::Remote::HTTP::Gitea::Error::CsrfError.new unless csrf

    res = send_request_cgi(
      'method' => 'POST',
      'uri' => uri,
      'vars_post' => gitea_helper_repo_migrate_post_data(name, uid, service, url, token, csrf),
      'keep_cookies' => true
    )
    if res&.code != 302 # possibly triggered by the [migrations] settings
      err = res&.get_html_document&.at('//div[contains(@class, flash-error)]/p')&.text
      raise Msf::Exploit::Remote::HTTP::Gitea::Error::MigrationError.new(err)
    end
    return res
  end

  # performs a gitea repository deletion
  #
  # @param path [String] Repository path (/username/reponame)
  # @param timeout [Integer] The maximum number of seconds to wait before the
  #   request times out
  # @return [Rex::Proto::Http::Response] the HTTP response object or raise
  #   CsrfError otherwise
  def gitea_remove_repo(path, timeout = 20)
    uri = gitea_url_repo_settings(path)
    res = send_request_cgi({
      'uri' => uri,
      'keep_cookies' => true
    }, timeout)
    return nil unless res
    return res if res&.code == 404 # return res if 404 to handling cleanup

    csrf = gitea_get_csrf(res)
    raise Msf::Exploit::Remote::HTTP::Gitea::Error::CsrfError.new unless csrf

    name = path.split('/').last
    send_request_cgi(
      'method' => 'POST',
      'uri' => uri,
      'vars_post' => gitea_helper_repo_remove_post_data(name, csrf),
      'keep_cookies' => true
    )
  end
end
