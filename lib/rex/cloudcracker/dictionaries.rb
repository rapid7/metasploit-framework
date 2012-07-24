require 'json'
require 'rex/proto/http'

module Rex
module CloudCracker
class Dictionaries

  attr_accessor :is_test

  def self.get_dictionaries(format)
    formats = %w[wpa ntlm cryptsha512 cryptmd5]

    if not formats.include? format
      raise "Format invalid"
    end

    uri = ""
    uri = uri + "/test" if @is_test
    uri = uri + "/api/" + format + "/dictionaries" 

    client = Rex::Proto::Http::Client.new("www.cloudcracker.com", 443, {}, true, 'SSLv3')

    req = client.request_cgi(
      'uri' => uri,
      'method' => 'GET'
      )

    res = client.send_recv(req, 300)

    if res.nil? or res.body.nil?
      raise Exception "Request for dictionaries failed."
    end

    return JSON.parse res.body
  end

end
end
end
