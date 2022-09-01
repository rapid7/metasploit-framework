require 'spec_helper'
require 'metasploit/framework/aws/client'

RSpec.describe Metasploit::Framework::Aws::Client do

  subject do
    s = Class.new(Msf::Auxiliary) do
      include Metasploit::Framework::Aws::Client
    end.new
    s.datastore['Region'] = 'us-east-1'
    s.datastore['RHOST'] = '127.0.0.1'
    s
  end

  let(:body_hash) { { 'a' => 'b', 'b' => 'c' } }

  let(:body) { 'a=b&b=c' }

  let(:value) { 'metasploit' }

  let(:key) { 'metasploit' }

  let(:headers) { { 'H1' => 1, 'H2' => 2 } }

  let(:headers_down_join) { headers.keys.map(&:downcase).join(';') }

  let(:digest) { 'ca6ac6af66c22d8acdd6e42a00a9a21a24a37e3fa6a018662fb6dbaabfe7a96d' }

  let(:body_digest) { '4044f25c89ec766b67d5e8c5d9e387cf209e740ee5ad65868f5a9f6e587acf43' }

  let(:signature) { 'ac297b1b72d956a81bf9d2d20bfd98bca632c0607f2a8c896779f08d19e637d6' }

  let(:creds) do
    {
      'AccessKeyId' => 'AWS_ACCESS_KEY_ID',
      'SecretAccessKey' => 'AWS_SECRET_ACCESS_KEY',
      'Token' => 'AWS_SESSION_TOKEN'
    }
  end

  let(:now) { "20161124T175843Z" }

  let(:service) { 'iam' }

  let(:auth_header) { "AWS4-HMAC-SHA256 Credential=#{creds.fetch('AccessKeyId')}/#{now[0, 8]}/#{subject.datastore.fetch('Region')}/#{service}/aws4_request, SignedHeaders=#{headers_down_join}, Signature=#{signature}" }

  it 'should create a SHA 265 digest' do
    d = subject.hexdigest(value)
    expect(d).to eq(digest)
    expect(subject.hexdigest(nil)).to be_nil
    expect(subject.hexdigest([])).to be_nil
  end

  it 'should perform proper hmac hashing' do
    hmac = subject.hmac(key, value)
    result = "\xD1?O\xA5\xFF\x7FT_\xC97\e\x01dp\x11)\x0FSL\xC3>\x1F\v\xA7\xD4\xEA\xB8\x99\xE0DW\xF7".force_encoding('ASCII-8BIT')
    expect(hmac).to eq(result)
    expect(subject.hmac([], value)).to be_nil
    expect(subject.hmac(key, {})).to be_nil
    expect(subject.hmac(key, nil)).to be_nil
    expect(subject.hmac(nil, value)).to be_nil
    expect(subject.hmac(1, 2)).to be_nil
    expect(subject.hmac(nil, nil)).to be_nil
  end

  it 'should create a hex hmac' do
    hexhmac = subject.hexhmac(key, value)
    expect(hexhmac).to eq("d13f4fa5ff7f545fc9371b01647011290f534cc33e1f0ba7d4eab899e04457f7")
    expect(subject.hexhmac([], value)).to be_nil
    expect(subject.hexhmac(key, {})).to be_nil
    expect(subject.hexhmac(key, nil)).to be_nil
    expect(subject.hexhmac(nil, value)).to be_nil
    expect(subject.hexhmac(1, 2)).to be_nil
    expect(subject.hexhmac(nil, nil)).to be_nil
  end

  it 'should create a request' do
    header_keys, request = subject.request_to_sign(headers, digest)
    expect(header_keys).to eq(headers_down_join)
    expect(request).to eq("POST\n/\n\nh1:1\nh2:2\n\n#{headers_down_join}\n#{digest}")
  end

  it 'should create a signed message' do
    h, s = subject.sign(creds, service, headers, digest, now)
    expect(h).to eq(headers_down_join)
    expect(s).to eq(signature)
  end

  it 'should create an Authorization header' do
    auth = subject.auth(creds, service, headers, digest, now)
    expect(auth).to eq(auth_header)
  end

  it 'should create the request body' do
    b = subject.body(body_hash)
    expect(b).to eq(body)
  end

  it 'should create proper headers' do
    h = subject.headers(creds, service, digest, now)
    expect(h.fetch('Content-Type')).to eq("application/x-www-form-urlencoded; charset=utf-8")
    expect(h.fetch('Accept-Encoding')).to be_empty
    expect(h.fetch('User-Agent')).to eq(Metasploit::Framework::Aws::Client::USER_AGENT)
    expect(h.fetch('X-Amz-Date')).to eq(now)
    expect(h.fetch('Host')).to eq(subject.datastore.fetch('RHOST'))
    expect(h.fetch('X-Amz-Content-Sha256')).to eq(digest)
    expect(h.fetch('Accept')).to eq('*/*')
    expect(h.fetch('X-Amz-Security-Token')).to eq(creds.fetch('Token'))
    expect(h.fetch('Authorization')).to eq("AWS4-HMAC-SHA256 Credential=AWS_ACCESS_KEY_ID/#{now[0, 8]}/#{subject.datastore.fetch('Region')}/#{service}/aws4_request, SignedHeaders=content-type;host;user-agent;x-amz-content-sha256;x-amz-date, Signature=275d7332d893de60eaf9f033e1f125f9f00e79c86b7b8902d620da778aff602b")
  end

  it 'should not error out with weird input' do
    expect { subject.print_results({}, 'Test') }.to raise_error(KeyError)
    expect { subject.print_results({ 'TestResponse' => nil }, 'Test') }.not_to raise_error
    expect(subject.print_results({ 'TestResponse' => [] }, 'Test')).to eq({})
  end

  it 'should not error out with non Hash values' do
    expect { subject.print_hsh(nil) }.not_to raise_error
    expect { subject.print_hsh([]) }.not_to raise_error
    expect { subject.print_hsh(-42) }.not_to raise_error
    expect { subject.print_hsh('A' * 5000) }.not_to raise_error
  end
end
