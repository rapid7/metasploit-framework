RSpec::Matchers.define :be_challenge do
  match do |actual_response|
    actual_response.status == 401 &&
    actual_response['WWW-Authenticate'] =~ /^Digest / &&
    actual_response.body.empty?
  end

  description do
    "a HTTP Digest challenge response"
  end
end
