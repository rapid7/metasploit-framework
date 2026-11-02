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
    allow(initial_http).to receive(:use_ssl=)
    allow(redirect_http).to receive(:use_ssl=)
    allow(Net::HTTP).to receive(:new).with('docs.example.test', 443).and_return(initial_http, redirect_http)
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
    expect(Net::HTTP).to receive(:new).with('archive.example.test', 8443).and_return(redirect_http)
    checker.send(:check_url, entry)
  end

  it 'updates TLS when following a redirect to HTTP' do
    redirect_response['location'] = 'http://archive.example.test/new'
    allow(Net::HTTP).to receive(:new).with('archive.example.test', 80).and_return(redirect_http)
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
    allow(Net::HTTP).to receive(:new).with('docs.example.test', 443).and_return(initial_http)
    expect(initial_http).to receive(:get).with('/old').exactly(described_class::MAX_REDIRECTS + 1).times.and_return(redirect_response)
    checker.send(:check_url, entry)
  end
end
