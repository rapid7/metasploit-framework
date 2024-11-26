# -*- coding: binary -*-

module Msf::Exploit::Remote::HTTP::Gitlab::Rest::V4::AccessTokens
  # Revoke a Gitlab access token via the v4 REST api
  #
  # @return [nil,GitLabClientError] nil if revoke, Msf::Exploit::Remote::HTTP::Gitlab::GitLabClientError otherwise
  def gitlab_revoke_personal_access_token(personal_access_token)
    res = send_request_cgi({
      'method' => 'DELETE',
      'uri' => normalize_uri(target_uri.path, '/api/v4/personal_access_tokens/self'),
      'ctype' => 'application/json',
      'headers' => {
        'PRIVATE-TOKEN' => personal_access_token
      }
    })

    raise Msf::Exploit::Remote::HTTP::Gitlab::Error::ClientError.new message: 'Request timed out' unless res

    raise Msf::Exploit::Remote::HTTP::Gitlab::Error::ClientError, "Failed to revoke access token.  Unexpected HTTP #{res.code} response." unless res.code == 204

    nil
  end
end
