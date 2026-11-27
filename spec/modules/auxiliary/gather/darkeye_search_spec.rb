require 'msf/base'
require 'msf/core/exploit/remote/http_client'

RSpec.describe 'DarkEye domain exposure search' do
  before(:context) do
    @framework = Msf::Simple::Framework.create('DisableDatabase' => true, 'DeferModuleLoads' => true)
    loader = Msf::Modules::Loader::Directory.new(@framework.modules)
    loader.load_module(File.join(Msf::Config.install_root, 'modules'), 'auxiliary', 'gather/darkeye_search')
  end

  after(:context) do
    @framework.threads.each(&:kill)
    Rex::ThreadFactory.provider = nil
  end

  subject(:mod) { @framework.modules.create('auxiliary/gather/darkeye_search') }
  let(:module_class) { mod.class }

  let(:item) { { 'id_source' => '1', 'website' => 'example.test', 'post_title' => 'Synthetic listing', 'leak_type' => 'ransomware_leak' } }
  let(:hibr) { { 'sources' => [item], 'has_next' => false } }
  let(:search) { { 'ransomware' => [item], 'breaches' => [], 'leads' => [], 'stealers' => [] } }

  def response(body, code = 200)
    result = Rex::Proto::Http::Response.new(code)
    result.body = body.is_a?(String) ? body : JSON.generate(body)
    result
  end

  def api_responses(*responses)
    allow(mod).to receive(:send_request_cgi).and_return(*responses)
  end

  before do
    mod.datastore['DOMAIN'] = 'example.test'
    mod.datastore['HIBR_API_KEY'] = 'synthetic-hibr-key'
    mod.datastore['BREACHHOUSE_API_KEY'] = 'synthetic-bh-key'
  end

  it 'returns one product-labelled report with both products' do
    api_responses(response(hibr), response(search))
    result = mod.lookup('example.test')
    expect(result).to include('provider' => 'DarkEye', 'count' => 2, 'status' => 'complete', 'truncated' => false)
    expect(result['records'].map { |record| record['product'] }).to eq(['HaveIBeenRansom', 'Breach House'])
  end

  %w[HIBR_API_KEY BREACHHOUSE_API_KEY].each do |option|
    it "runs independently without #{option}" do
      mod.datastore[option] = nil
      api_responses(response(option == 'HIBR_API_KEY' ? search : hibr))
      expect(mod.lookup('example.test')).to include('count' => 1, 'status' => 'complete')
      expect(mod).to have_received(:send_request_cgi).once
    end
  end

  [401, 403, 429, 500, 302].each do |status|
    it "preserves the other product after HTTP #{status}, without following redirects" do
      api_responses(response({}, status), response(search))
      result = mod.lookup('example.test')
      expect(result).to include('count' => 1, 'products' => ['Breach House'], 'status' => 'partial')
      expect(mod).to have_received(:send_request_cgi).twice
    end
  end

  it 'does not save an empty success if every product fails' do
    api_responses(nil)
    allow(mod).to receive(:print_warning)
    expect(mod).not_to receive(:store_loot)
    expect { mod.run }.to raise_error(Msf::Auxiliary::Failed, /Every configured/)
  end

  it 'saves the JSON report through the framework loot API' do
    api_responses(response(hibr), response(search))
    allow(mod).to receive(:print_status)
    allow(mod).to receive(:print_good)
    expect(mod).to receive(:store_loot) do |kind, mime, host, body, filename, _description|
      expect([kind, mime, host, filename]).to eq(['darkeye.metadata', 'application/json', nil, 'darkeye.json'])
      expect(JSON.parse(body)).to include('count' => 2, 'provider' => 'DarkEye')
      '/synthetic/darkeye.json'
    end
    mod.run
  end

  it 'does not retain leaked content, links, keys or terminal controls' do
    hibr['sources'][0].merge!('description' => 'PRIVATE', 'data' => 'PRIVATE', 'password' => 'PRIVATE', 'download_link' => 'PRIVATE', 'post_title' => "\e[31msynthetic-hibr-key\u202e")
    api_responses(response(hibr), response(search))
    report = JSON.generate(mod.lookup('example.test'))
    expect(report).not_to match(/PRIVATE|synthetic-hibr-key|synthetic-bh-key|\\u001b|\\u202e/)
  end

  it 'uses isolated verified HTTPS clients and bearer headers' do
    api_responses(response(hibr), response(search))
    requests = []
    allow(mod).to receive(:send_request_cgi) do |request|
      requests << request
      response(request['rhost'] == 'haveibeenransom.com' ? hibr : search)
    end
    mod.lookup('example.test')
    expect(requests.map { |request| request['headers']['Authorization'] }).to eq(['Bearer synthetic-hibr-key', 'Bearer synthetic-bh-key'])
    expect(requests.map { |request| request['client'].object_id }.uniq.length).to eq(2)
    requests.each do |request|
      expect(request).to include('SSL' => true, 'rport' => 443, 'cookie' => '', 'keep_cookies' => false, 'preferred_auth' => 'None')
      expect(request['client']).to be_a(module_class::VerifiedHttpClient)
    end
  end

  it 'rejects malformed JSON before the framework parser can log the body' do
    bad = response('PRIVATE synthetic-hibr-key {')
    api_responses(bad, response(search))
    expect(bad).not_to receive(:get_json_document)
    result = mod.lookup('example.test')
    expect(result['errors']).to eq([{ 'product' => 'HaveIBeenRansom', 'error' => 'API returned invalid JSON' }])
  end

  it 'does not expose exception messages containing a token' do
    allow(mod).to receive(:send_request_cgi).and_raise(OpenSSL::SSL::SSLError, 'synthetic-hibr-key')
    expect(JSON.generate(mod.lookup('example.test'))).not_to include('synthetic-hibr-key')
  end

  it 'follows pagination through empty pages and deduplicates metadata' do
    api_responses(response('sources' => [], 'has_next' => true), response('results' => [item, item], 'pagination' => { 'has_next' => false }))
    expect(mod.hibr_lookup('example.test', 'synthetic-hibr-key')).to include(truncated: false, records: [mod.metadata_record('HaveIBeenRansom', 'ransomware', item)])
    expect(mod).to have_received(:send_request_cgi).with(hash_including('uri' => '/api/metadata/domain/example.test/2'))
  end

  it 'discards incomplete HIBR records when a later page fails' do
    api_responses(response('sources' => [item], 'has_next' => true), response({}, 500), response(search))
    expect(mod.lookup('example.test')).to include('count' => 1, 'products' => ['Breach House'], 'status' => 'partial')
  end

  [true, false].each do |has_next|
    it "handles an exact record limit with has_next=#{has_next}" do
      mod.datastore['MAX_RECORDS'] = 1
      api_responses(response('sources' => [item], 'has_next' => has_next))
      expect(mod.hibr_lookup('example.test', 'key')[:truncated]).to eq(has_next)
      expect(mod).to have_received(:send_request_cgi).once
    end
  end

  it 'marks the page cap as truncated' do
    mod.datastore['MAX_PAGES'] = 1
    api_responses(response('sources' => [], 'has_next' => true))
    expect(mod.hibr_lookup('example.test', 'key')).to eq(records: [], truncated: true)
  end

  it 'keeps categories distinct and detects truncation before filtering' do
    search['ransomware'] = { 'results' => [{ 'website' => 'unrelated.test' }], 'total' => 2 }
    search['stealers'] = [item, item]
    search['leads'] = [item]
    api_responses(response(search))
    result = mod.breach_house_lookup('example.test', 'key')
    expect(result[:truncated]).to be(true)
    expect(result[:records].map { |record| record['category'] }).to eq(%w[leads stealer])
  end

  [
    ['example.test', '', true], ['https://sub.example.test/path', '', true],
    ['notexample.test', '', false], ['example.test.evil.test', '', false],
    ['unrelated.test', 'example.test', false], ['', 'Leak at example.test.', true],
    ['', 'example.test.evil.test', false], ['', 'notexample.test', false]
  ].each do |website, title, expected|
    it "matches domain boundaries for #{website.inspect} / #{title.inspect}" do
      expect(mod.domain_match?({ 'website' => website, 'title' => title }, 'example.test')).to eq(expected)
    end
  end

  [{}, { 'sources' => nil }, { 'sources' => [{}], 'has_next' => false }, { 'sources' => [], 'has_next' => 'false' }].each do |body|
    it "rejects malformed HIBR metadata #{body}" do
      api_responses(response(body))
      expect { mod.hibr_lookup('example.test', 'key') }.to raise_error(module_class::LookupError)
    end
  end

  [{}, { 'ransomware' => nil }, { 'ransomware' => { 'results' => [], 'total' => -1 }, 'breaches' => [], 'leads' => [], 'stealers' => [] }].each do |body|
    it "rejects malformed Breach House metadata #{body}" do
      api_responses(response(body))
      expect { mod.breach_house_lookup('example.test', 'key') }.to raise_error(module_class::LookupError)
    end
  end

  ['http://example.test', '192.0.2.1', '../example.test', 'example.test?key=x', 'a..test', '-example.test', 'localhost'].each do |domain|
    it "rejects invalid domain #{domain} without network requests" do
      mod.datastore['DOMAIN'] = domain
      expect(mod).not_to receive(:send_request_cgi)
      expect { mod.run }.to raise_error(Msf::OptionValidateError)
    end
  end

  it 'normalizes uppercase and one trailing dot' do
    expect(mod.normalize_domain(' ExAmPlE.TeSt. ')).to eq('example.test')
  end

  it 'rejects missing keys before contacting any API' do
    mod.datastore['HIBR_API_KEY'] = nil
    mod.datastore['BREACHHOUSE_API_KEY'] = nil
    expect(mod).not_to receive(:send_request_cgi)
    expect { mod.run }.to raise_error(Msf::OptionValidateError)
  end

  it 'rejects header injection' do
    mod.datastore['HIBR_API_KEY'] = "key\r\nInjected: value"
    expect { mod.validate }.to raise_error(Msf::OptionValidateError)
  end

  { 'MAX_PAGES' => 21, 'MAX_RECORDS' => 0, 'SEARCH_LIMIT' => 201, 'HttpClientTimeout' => 0 }.each do |name, value|
    it "rejects invalid #{name}" do
      mod.datastore[name] = value
      expect { mod.validate }.to raise_error(Msf::OptionValidateError)
    end
  end
  describe 'TLS verification before sending the API key' do
    let(:client) { module_class::VerifiedHttpClient.new('api.example.test', 443, {}, true) }
    let(:certificate) do
      key = OpenSSL::PKey::RSA.new(2048)
      cert = OpenSSL::X509::Certificate.new
      cert.version = 2
      cert.serial = 1
      cert.subject = OpenSSL::X509::Name.parse('/CN=api.example.test')
      cert.issuer = cert.subject
      cert.public_key = key.public_key
      cert.not_before = Time.utc(2026, 1, 1)
      cert.not_after = Time.utc(2030, 1, 1)
      cert.sign(key, OpenSSL::Digest.new('SHA256'))
      cert
    end
    let(:socket) { double('TLS socket', peer_cert: certificate, peer_cert_chain: [certificate]) }

    it 'rejects an untrusted certificate chain' do
      expect(client).to receive(:close)
      expect { client.verify_peer!(socket) }.to raise_error(OpenSSL::SSL::SSLError, 'API certificate verification failed')
    end

    it 'rejects a hostname mismatch even when the chain is trusted' do
      store = OpenSSL::X509::Store.new
      allow(OpenSSL::X509::Store).to receive(:new).and_return(store)
      allow(store).to receive(:verify).and_return(true)
      wrong_host = module_class::VerifiedHttpClient.new('other.example.test', 443, {}, true)
      expect { wrong_host.verify_peer!(socket) }.to raise_error(OpenSSL::SSL::SSLError)
    end

    it 'accepts a trusted chain for the expected hostname' do
      store = OpenSSL::X509::Store.new
      allow(OpenSSL::X509::Store).to receive(:new).and_return(store)
      allow(store).to receive(:verify).and_return(true)
      expect { client.verify_peer!(socket) }.not_to raise_error
    end
  end
end
