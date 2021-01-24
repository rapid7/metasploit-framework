
RSpec.describe Msf::OptHTTPRhostURL do
  subject(:opt) { described_class.new('RHOST_HTTP_URL') }

  valid_values = [
    { value: 'http://example.com', normalized: { 'RHOSTS' => 'example.com', 'RPORT' => 80, 'SSL' => false, 'TARGETURI' => '/', 'URI' => '/', 'VHOST' => 'example.com', 'HttpUsername' => '', 'HttpPassword' => '' } },
    { value: 'https://example.com', normalized: { 'RHOSTS' => 'example.com', 'RPORT' => 443, 'SSL' => true, 'TARGETURI' => '/', 'URI' => '/', 'VHOST' => 'example.com', 'HttpUsername' => '', 'HttpPassword' => '' } },
    { value: 'example.com', normalized: { 'RHOSTS' => 'example.com', 'RPORT' => 80, 'SSL' => false, 'TARGETURI' => '/', 'URI' => '/', 'VHOST' => 'example.com', 'HttpUsername' => '', 'HttpPassword' => '' } },
    { value: 'http://user:pass@example.com:1234/somePath', normalized: { 'RHOSTS' => 'example.com', 'RPORT' => 1234, 'SSL' => false, 'TARGETURI' => '/somePath', 'URI' => '/somePath', 'VHOST' => 'example.com', 'HttpUsername' => 'user', 'HttpPassword' => 'pass' } },
    { value: 'http://127.0.0.1', normalized: { 'RHOSTS' => '127.0.0.1', 'RPORT' => 80, 'SSL' => false, 'TARGETURI' => '/', 'URI' => '/', 'VHOST' => nil, 'HttpUsername' => '', 'HttpPassword' => '' } }
  ]

  invalid_values = [
    { value: '192.0.2.0/24' },
    { value: '192.0.2.0-255' },
    { value: '192.0.2.0,1-255' },
    { value: '192.0.2.*' },
    { value: '192.0.2.0-192.0.2.255' }
  ]

  it_behaves_like 'an option', valid_values, invalid_values, 'rhost http url'

  describe '#calculate_value' do
    [
      { expected_url: 'http://example.com', datastore: { 'RHOSTS' => 'example.com', 'RPORT' => 80, 'SSL' => false, 'TARGETURI' => '', 'URI' => '', 'VHOST' => 'example.com', 'HttpUsername' => '', 'HttpPassword' => '' } },
      { expected_url: 'https://example.com', datastore: { 'RHOSTS' => 'example.com', 'RPORT' => 443, 'SSL' => true, 'TARGETURI' => '', 'URI' => '', 'VHOST' => 'example.com', 'HttpUsername' => '', 'HttpPassword' => '' } },
      { expected_url: 'http://user:pass@example.com:1234/somePath', datastore: { 'RHOSTS' => 'example.com', 'RPORT' => 1234, 'SSL' => false, 'TARGETURI' => '/somePath', 'URI' => '/somePath', 'VHOST' => 'example.com', 'HttpUsername' => 'user', 'HttpPassword' => 'pass' } },
      { expected_url: 'http://127.0.0.1', datastore: { 'RHOSTS' => '127.0.0.1', 'RPORT' => 80, 'SSL' => false, 'TARGETURI' => '', 'URI' => '', 'VHOST' => nil, 'HttpUsername' => '', 'HttpPassword' => '' } },
      { expected_url: 'http://example.com', datastore: { 'RHOSTS' => '127.0.0.1', 'RPORT' => 80, 'SSL' => false, 'TARGETURI' => '', 'URI' => '', 'VHOST' => 'example.com', 'HttpUsername' => '', 'HttpPassword' => '' } }
    ].each do |test|
      context test[:datastore].to_s do
        it "should return #{test[:expected_url]}" do
          expect(subject.calculate_value(test[:datastore])).to eq(test[:expected_url])
        end
      end
    end
  end

  describe '#valid?' do
    [
      { expected: true, value: { 'VHOST' => nil, 'RHOSTS' => '127.0.0.1', 'RPORT' => 80, 'SSL' => false, 'TARGETURI' => '/', 'URI' => '/', 'HttpUsername' => '', 'HttpPassword' => '' } },
      { expected: true, value: 'google.com' },
      { expected: true, value: 'https://google.com' },
      { expected: true, value: '127.0.0.1' },
      { expected: true, value: 'http://127.0.0.1/' },
      { expected: true, value: nil }, # RHOST_HTTP_URL does not have to be set, so nil should return true.
      { expected: false, value: { 'VHOST' => nil, 'RHOSTS' => '', 'RPORT' => 80, 'SSL' => false, 'TARGETURI' => '/', 'URI' => '/', 'HttpUsername' => '', 'HttpPassword' => '' } },
      { expected: false, value: {} },
      { expected: false, value: '' }
    ].each do |test|
      context test[:value].to_s do
        it "should return #{test[:expected]}" do
          expect(subject.valid?(test[:value])).to eq(test[:expected])
        end
      end
    end
  end
end
