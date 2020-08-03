require 'msf/core/opt_http_rhost_url'

RSpec.describe Msf::OptHTTPRhostURL do
  subject(:opt) { described_class.new('RHOST_HTTP_URL') }

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


  calculate_values = [
      { value: 'http://example.com', normalized: { 'RHOSTS' => 'example.com', 'RPORT' => 80, 'SSL' => false, 'TARGETURI' => '', 'URI' => '', 'VHOST' => 'example.com', 'HttpUsername' => '', 'HttpPassword' => '' } },
      { value: 'https://example.com', normalized: { 'RHOSTS' => 'example.com', 'RPORT' => 443, 'SSL' => true, 'TARGETURI' => '', 'URI' => '', 'VHOST' => 'example.com', 'HttpUsername' => '', 'HttpPassword' => '' } },
      { value: 'http://user:pass@example.com:1234/somePath', normalized: { 'RHOSTS' => 'example.com', 'RPORT' => 1234, 'SSL' => false, 'TARGETURI' => '/somePath', 'URI' => '/somePath', 'VHOST' => 'example.com', 'HttpUsername' => 'user', 'HttpPassword' => 'pass' } },
      { value: 'http://127.0.0.1', normalized: { 'RHOSTS' => '127.0.0.1', 'RPORT' => 80, 'SSL' => false, 'TARGETURI' => '', 'URI' => '', 'VHOST' => nil, 'HttpUsername' => '', 'HttpPassword' => '' } }
  ]

  calculate_values_no_schema = [
      { value: 'example.com', normalized: { 'RHOSTS' => 'example.com', 'RPORT' => 80, 'SSL' => false, 'TARGETURI' => '', 'URI' => '', 'VHOST' => 'example.com', 'HttpUsername' => '', 'HttpPassword' => '' } },
      { value: 'example.com:443', normalized: { 'RHOSTS' => 'example.com', 'RPORT' => 443, 'SSL' => false, 'TARGETURI' => '', 'URI' => '', 'VHOST' => 'example.com', 'HttpUsername' => '', 'HttpPassword' => '' } },
      { value: 'user:pass@example.com:1234/somePath', normalized: { 'RHOSTS' => 'example.com', 'RPORT' => 1234, 'SSL' => false, 'TARGETURI' => '/somePath', 'URI' => '/somePath', 'VHOST' => 'example.com', 'HttpUsername' => 'user', 'HttpPassword' => 'pass' } },
      { value: '127.0.0.1', normalized: { 'RHOSTS' => '127.0.0.1', 'RPORT' => 80, 'SSL' => false, 'TARGETURI' => '', 'URI' => '', 'VHOST' => nil, 'HttpUsername' => '', 'HttpPassword' => '' } }
  ]

  describe '#calculate_value' do
    calculate_values.each do | url |

      context url[:normalized].to_s do
        it "should return #{url[:value]}" do
          expect(subject.calculate_value(url[:normalized])).to eq(URI(url[:value]))
        end
      end
    end
  end

  describe '#calculate_value missing scheme' do
    calculate_values_no_schema.each do | url |

      context url[:normalized].to_s do
        it "should return #{url[:value]}" do
          expect(subject.calculate_value(url[:normalized])).to eq(URI('http://' + url[:value]))
        end
      end
    end
  end

end
