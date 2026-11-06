require 'spec_helper'
require 'tmpdir'
require_relative '../../../tools/dev/detect_dead_reference_links'

RSpec.describe UrlChecker do
  let(:checker) { described_class.new([]) }
  let(:entry) { { url: 'URL-https://docs.example.test/old', path: 'example.rb' } }
  let(:initial_http) { instance_double(Net::HTTP) }
  let(:redirect_http) { instance_double(Net::HTTP) }
  let(:redirect_response) { http_response(Net::HTTPFound, '302', 'Found', 'https://docs.example.test/new') }
  let(:final_response) { http_response(Net::HTTPOK, '200', 'OK') }

  def http_response(klass, code, message, location = nil)
    response = klass.new('1.1', code, message)
    response['location'] = location if location
    response
  end

  around do |example|
    Dir.mktmpdir('reference-links') do |directory|
      Dir.chdir(directory) { example.run }
    end
  end

  before do
    allow(checker).to receive(:save_progress)
    allow(checker).to receive(:fetch_wayback_snapshot)
    allow(Addrinfo).to receive(:getaddrinfo).and_return([Addrinfo.ip('93.184.216.34')])
    allow(initial_http).to receive(:ipaddr=)
    allow(redirect_http).to receive(:ipaddr=)
    allow(initial_http).to receive(:use_ssl=)
    allow(redirect_http).to receive(:use_ssl=)
    allow(Net::HTTP).to receive(:new).with('docs.example.test', 443, nil).and_return(initial_http, redirect_http)
    allow(initial_http).to receive(:get).with('/old').and_return(redirect_response)
    allow(initial_http).to receive(:get).with('/new').and_return(final_response)
    allow(redirect_http).to receive(:get).with('/new').and_return(final_response)
  end

  context 'when the redirect destination is missing' do
    let(:final_response) { http_response(Net::HTTPNotFound, '404', 'Not Found') }

    it 'reports the final response status instead of calling the redirect alive' do
      expect(checker.send(:check_url, entry)[:status]).to eq('Not Alive (Status Code: 404)')
    end
  end

  it 'keeps successful redirects alive' do
    expect(checker.send(:check_url, entry)[:status]).to eq('Alive')
  end

  it 'requests a relative location with its query string' do
    redirect_response['location'] = '/new?version=1'
    expect(redirect_http).to receive(:get).with('/new?version=1').and_return(final_response)
    checker.send(:check_url, entry)
  end

  it 'connects to the destination host and port for cross-host redirects' do
    redirect_response['location'] = 'https://archive.example.test:8443/new'
    expect(Net::HTTP).to receive(:new).with('archive.example.test', 8443, nil).and_return(redirect_http)
    checker.send(:check_url, entry)
  end

  it 'updates TLS when following a redirect to HTTP' do
    redirect_response['location'] = 'http://archive.example.test/new'
    allow(Net::HTTP).to receive(:new).with('archive.example.test', 80, nil).and_return(redirect_http)
    expect(redirect_http).to receive(:use_ssl=).with(false)
    checker.send(:check_url, entry)
  end

  it 'preserves the initial request error' do
    allow(initial_http).to receive(:get).with('/old').and_raise(IOError, 'connection lost')
    expect(checker.send(:check_url, entry)[:status]).to eq('Error: connection lost')
  end

  it 'preserves an error while requesting the redirect destination' do
    allow(initial_http).to receive(:get).with('/new').and_raise(IOError, 'redirect connection lost')
    allow(redirect_http).to receive(:get).with('/new').and_raise(IOError, 'redirect connection lost')
    expect(checker.send(:check_url, entry)[:status]).to eq('Error: redirect connection lost')
  end

  it 'keeps successful non-redirected responses alive' do
    allow(initial_http).to receive(:get).with('/old').and_return(final_response)
    expect(checker.send(:check_url, entry)[:status]).to eq('Alive')
  end

  it 'keeps the existing redirect limit' do
    redirect_response['location'] = 'https://docs.example.test/old'
    allow(Net::HTTP).to receive(:new).with('docs.example.test', 443, nil).and_return(initial_http)
    expect(initial_http).to receive(:get).with('/old').exactly(described_class::MAX_REDIRECTS + 1).times.and_return(redirect_response)
    checker.send(:check_url, entry)
  end

  it 'passes an initial IPv6 literal without brackets to DNS and Net::HTTP' do
    address = '2606:4700:4700::1111'
    entry[:url] = "URL-https://[#{address}]/old"
    expect(Addrinfo).to receive(:getaddrinfo).with(address, 443, nil, :STREAM).and_return([Addrinfo.ip(address)])
    expect(Net::HTTP).to receive(:new).with(address, 443, nil).and_return(initial_http)
    allow(initial_http).to receive(:get).with('/old').and_return(final_response)
    checker.send(:check_url, entry)
  end

  it 'passes a redirected IPv6 literal without brackets to Net::HTTP' do
    address = '2606:4700:4700::1111'
    redirect_response['location'] = "https://[#{address}]/new"
    expect(Net::HTTP).to receive(:new).with(address, 443, nil).and_return(redirect_http)
    checker.send(:check_url, entry)
  end

  it 'pins the connection to the resolved and validated address' do
    expect(initial_http).to receive(:ipaddr=).with('93.184.216.34')
    checker.send(:check_url, entry)
  end

  %w[127.0.0.1 169.254.169.254 10.0.0.1 ::1 fe80::1 fd00::1 ::ffff:127.0.0.1].each do |address|
    it "rejects a redirect resolving to #{address} before creating a client" do
      redirect_response['location'] = 'https://internal.example.test/new'
      allow(Addrinfo).to receive(:getaddrinfo).with('internal.example.test', 443, nil, :STREAM).and_return([Addrinfo.ip(address)])
      expect(Net::HTTP).not_to receive(:new).with('internal.example.test', 443, nil)
      expect(checker.send(:check_url, entry)[:status]).to eq('Error: Refusing non-public destination: internal.example.test')
    end
  end

  it 'rejects mixed public and private DNS answers' do
    allow(Addrinfo).to receive(:getaddrinfo).and_return([Addrinfo.ip('93.184.216.34'), Addrinfo.ip('192.168.1.1')])
    expect(Net::HTTP).not_to receive(:new)
    expect(checker.send(:check_url, entry)[:status]).to eq('Error: Refusing non-public destination: docs.example.test')
  end

  it 'rejects non-HTTP redirect schemes' do
    redirect_response['location'] = 'file:///etc/hosts'
    expect(checker.send(:check_url, entry)[:status]).to eq('Error: Only absolute HTTP(S) destinations are supported')
  end

  it 'rejects an initial private destination' do
    allow(Addrinfo).to receive(:getaddrinfo).and_return([Addrinfo.ip('192.168.1.1')])
    expect(Net::HTTP).not_to receive(:new)
    expect(checker.send(:check_url, entry)[:status]).to eq('Error: Refusing non-public destination: docs.example.test')
  end

  it 'encodes the cleaned original URL as a single Wayback query parameter' do
    result = { url: 'URL-https://docs.example.test/page?a=1&b=2#section' }
    archive_http = instance_double(Net::HTTP, :use_ssl= => nil, :ipaddr= => nil)
    allow(Net::HTTP).to receive(:new).with('archive.org', 443, nil).and_return(archive_http)
    allow(checker).to receive(:handle_wayback_response)
    allow(checker).to receive(:fetch_wayback_snapshot).and_call_original
    encoded_url = URI.encode_www_form_component('https://docs.example.test/page?a=1&b=2#section')
    expect(archive_http).to receive(:get).with("/wayback/available?url=#{encoded_url}").and_return(final_response)
    checker.send(:fetch_wayback_snapshot, result)
  end
end
