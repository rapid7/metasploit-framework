require 'rex/proto/dns'

RSpec.describe Rex::Proto::DNS::Cache do
  subject(:cache) { described_class.new }

  # cache_record no-ops unless the monitor is running; pretend it is so the
  # validation path actually runs during the test
  before { cache.instance_variable_set(:@monitor_thread, true) }

  describe '#cache_record' do
    it 'caches a record whose name is a valid hostname' do
      record = Dnsruby::RR.create(name: 'good.example.com.', type: 'A', address: '192.0.2.10')
      cache.cache_record(record)
      expect(cache.records.keys).to include(record)
    end

    it 'skips a forwarded record whose name is not a valid hostname instead of raising' do
      # Regression: real upstream responses carry records whose names fail
      # MATCH_HOSTNAME (e.g. SRV-style underscore labels). Caching them used to
      # raise and kill the dispatch thread; they must be skipped silently.
      record = Dnsruby::RR.create(name: '_ldap._tcp.example.com.', type: 'A', address: '192.0.2.20')
      expect { cache.cache_record(record) }.not_to raise_error
      expect(cache.records).to be_empty
    end
  end
end
