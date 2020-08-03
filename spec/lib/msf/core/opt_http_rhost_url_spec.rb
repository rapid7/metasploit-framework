require 'msf/core/opt_http_rhost_url'

RSpec.describe Msf::OptHTTPRhostURL do
  subject(:opt) { described_class }

  valid_values = [
    { value: 'http://example.com', normalized: { 'RHOSTS' => 'example.com', 'RPORT' => 80, 'SSL' => false, 'TARGETURI' => '', 'URI' => '', 'VHOST' => 'example.com', 'HttpUsername' => '', 'HttpPassword' => '' } },
    { value: 'https://example.com', normalized: { 'RHOSTS' => 'example.com', 'RPORT' => 443, 'SSL' => true, 'TARGETURI' => '', 'URI' => '', 'VHOST' => 'example.com', 'HttpUsername' => '', 'HttpPassword' => '' } },
    { value: 'example.com', normalized: { 'RHOSTS' => 'example.com', 'RPORT' => 80, 'SSL' => false, 'TARGETURI' => '', 'URI' => '', 'VHOST' => 'example.com', 'HttpUsername' => '', 'HttpPassword' => '' } },
    { value: 'http://user:pass@example.com:1234/somePath', normalized: { 'RHOSTS' => 'example.com', 'RPORT' => 1234, 'SSL' => false, 'TARGETURI' => '/somePath', 'URI' => '/somePath', 'VHOST' => 'example.com', 'HttpUsername' => 'user', 'HttpPassword' => 'pass' } },
    { value: 'http://127.0.0.1', normalized: { 'RHOSTS' => '127.0.0.1', 'RPORT' => 80, 'SSL' => false, 'TARGETURI' => '', 'URI' => '', 'VHOST' => nil, 'HttpUsername' => '', 'HttpPassword' => '' } }
  ]

  invalid_values = [
    { value: '192.0.2.0/24' },
    { value: '192.0.2.0-255' },
    { value: '192.0.2.0,1-255' },
    { value: '192.0.2.*' },
    { value: '192.0.2.0-192.0.2.255' }
  ]

  it_behaves_like 'an option', valid_values, invalid_values, 'rhost http url'
end
