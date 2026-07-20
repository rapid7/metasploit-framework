# Minimal JWT wrapper which only decodes the base64 header/claim values,
# and doesn't encode/validate JWT tokens.
#
# Note that swapping this out for a third-party gem will work, but
# there may be potential security issues with the key id (kid) claim etc,
# which would need to be reviewed.
require 'base64'

class Msf::Exploit::Remote::HTTP::JWT
  attr_reader :payload, :header, :signature

  def initialize(payload:, header:, signature:)
    @payload = payload
    @header = header
    @signature = signature
  end

  def self.base64_url(data)
    Base64.urlsafe_encode64(data).gsub('=', '')
  end

  def self.encode(payload, key, algorithm = 'HS256', header_fields = {})
    header = base64_url(%({"alg":"#{algorithm}","typ":"JWT"}))

    payload = base64_url(payload)

    case algorithm
    when 'HS256'
      signature = base64_url(OpenSSL::HMAC.digest('SHA256', key, "#{header}.#{payload}"))
    else
      raise NotImplementedError, "#{algorithm} currently not supported"
    end

    "#{header}.#{payload}.#{signature}"
  end

  def self.decode(jwt, _key = nil, _verify = true, _options = {})
    header, payload, signature = jwt.split('.', 3)
    raise ArgumentError, 'Invalid JWT format' if header.nil? || payload.nil? || signature.nil?

    header = JSON.parse(Rex::Text.decode_base64(header))
    payload = JSON.parse(Rex::Text.decode_base64(payload))

    new(payload: payload, header: header, signature: signature)
  end
end
