# -*- coding:binary -*-
require 'spec_helper'

require 'rex/proto/http/client_request'


shared_context "with no evasions" do
  before(:each) do
    client_request.opts['uri_dir_self_reference'] = false
    client_request.opts['uri_fake_params_start'] = false
    client_request.opts['uri_full_url'] = false
  end

  it "should return the unmodified uri" do
    client_request.send(:set_uri).should == "/"
  end
end


shared_context "with 'uri_dir_self_reference'" do
  before(:each) do
    client_request.opts['uri_dir_self_reference'] = true
  end

  it "should have a self reference" do
    client_request.send(:set_uri).should include("/./")
    client_request.to_s.should include("/./")
  end
end


shared_context "with 'uri_dir_fake_relative'" do
  before(:each) do
    client_request.opts['uri_dir_fake_relative'] = true
  end

  it "should contain sequences of '../'" do
    client_request.send(:set_uri).should include("../")
    client_request.to_s.should include("../")
  end

end


shared_context "with 'uri_full_url'" do

  before(:each) do
    client_request.opts['uri_full_url'] = true
  end

  before(:each) do
    client_request.opts['vhost'] = host
  end

  context "with ipv4 host" do
    let(:host) { '192.0.2.1' }

    it_behaves_like "uri_full_url"
  end

  context "with ipv6 host" do
    let(:host) { '2001:DB8::1' }

    it_behaves_like "uri_full_url"
  end

  context "with dns host" do
    let(:host) { 'www.example.com' }

    it_behaves_like "uri_full_url"
  end

end

shared_examples "uri_full_url" do

  it "#set_uri should have the host in the URI" do
    client_request.send(:set_uri).should start_with("http://#{host}/")
  end

end


describe Rex::Proto::Http::ClientRequest do

  default_options = {
    # All of these should be what you get when you pass in empty
    # options, but of course that would make it too easy
    'uri' => '/',
    'method' => "GET",
    'proto' => "HTTP",
    'connection' => "close",
    'version' => "1.1",
    'port' => 80,
  }

  [
    [ "with reasonable default options",
      default_options.merge({
        'agent' => "Mozilla/4.0 (compatible; Metasploit RSPEC)",
        'vhost' => 'www.example.com',
      }),
      {
        :set_uri               => { :result => "/" },
        :set_method            => { :result => "GET" },
        :set_version           => { :result => "HTTP/1.1\r\n" },
        :set_uri_prepend       => { :result => "" },
        :set_uri_append        => { :result => "" },
        :set_agent_header      => { :result => "User-Agent: Mozilla/4.0 (compatible; Metasploit RSPEC)\r\n" },
        :set_host_header       => { :result => "Host: www.example.com\r\n" },
        :set_formatted_header  => { :args => ["Foo", "Bar"], :result => "Foo: Bar\r\n" },
        :set_formatted_header  => { :args => ["foo", "Bar"], :result => "foo: Bar\r\n" },
        :set_formatted_header  => { :args => ["Foo", "Bar\twith\ttabs"], :result => "Foo: Bar\twith\ttabs\r\n" },
        :set_formatted_header  => { :args => ["Foo\twith\tabs", "Bar"], :result => "Foo\twith\tabs: Bar\r\n" },
      }
    ],

    [ "with header folding",
      default_options.merge({
        'agent' => "Mozilla/4.0 (compatible; Metasploit RSPEC)",
        'header_folding' => true,
      }),
      {
        :set_uri               => { :result => "/" },
        :set_method            => { :result => "GET" },
        :set_version           => { :result => "HTTP/1.1\r\n" },
        :set_agent_header      => { :result => "User-Agent:\r\n\tMozilla/4.0 (compatible; Metasploit RSPEC)\r\n" },
        :set_cookie_header     => { :result => "" },
        :set_connection_header => { :result => "Connection:\r\n\tclose\r\n" },
        :set_formatted_header  => { :args => ["Foo", "Bar"], :result => "Foo:\r\n\tBar\r\n" },
        :set_formatted_header  => { :args => ["foo", "Bar"], :result => "foo:\r\n\tBar\r\n" },
        :set_formatted_header  => { :args => ["Foo", "Bar\twith\ttabs"], :result => "Foo:\r\n\tBar\twith\ttabs\r\n" },
        :set_formatted_header  => { :args => ["Foo\twith\tabs", "Bar"], :result => "Foo\twith\tabs:\r\n\tBar\r\n" },
      }
    ],

    [ "with ipv6 host",
      default_options.merge({
        'vhost' => "2001:DB8::1",
      }),
      {
        :set_host_header       => { :result => "Host: [2001:DB8::1]\r\n" },
      }
    ],

    [ "with ipv6 host and non-default port",
      default_options.merge({
        'port' => 1234,
        'vhost' => "2001:DB8::1",
      }),
      {
        :set_host_header       => { :result => "Host: [2001:DB8::1]:1234\r\n" },
      }
    ]
  ].each do |c, opts, expectations|
    context c do
      subject(:client_request) { Rex::Proto::Http::ClientRequest.new(opts) }

      expectations.each do |meth, things|
        args = things[:args] || []
        result = things[:result]
        describe "##{meth}" do
          it "should return #{result.inspect}" do
            client_request.send(meth, *args).should == result
          end
        end
      end

    end
  end

  subject(:client_request) { Rex::Proto::Http::ClientRequest.new(default_options) }

  context "with GET paramaters" do
    subject(:client_request) {
      options_with_params = default_options.merge({
        'uri_encode_mode' => encode_mode,
        'encode_params' => encode_params,
        'encode' => false,
        'vars_get' => vars_get,
      })
      Rex::Proto::Http::ClientRequest.new(options_with_params)
    }
    # default
    let(:encode_mode) { 'hex-normal' }

    let(:vars_get) do
      {
        'foo[]'      => 'bar',
        'bar'        => 'baz',
        'frobnicate' => 'the froozle?',
      }
    end

    context "with 'pad_get_params'" do
      let(:encode_params) { true }
      it "should ..." do
        old = client_request.opts['pad_get_params']
        client_request.opts['pad_get_params'] = true

        client_request.opts['pad_get_params_count'] = 0
        client_request.to_s.split("&").length.should == vars_get.length

        client_request.opts['pad_get_params_count'] = 10
        client_request.to_s.split("&").length.should == vars_get.length + 10

        client_request.opts['pad_get_params'] = old
      end
    end

    context "without 'encode_params'" do
      let(:encode_params) { false }
      it "should contain the unaltered params" do
        str = client_request.to_s
        str.should include("foo[]=bar")
        str.should include("bar=baz")
        str.should include("frobnicate=the froozle?")
      end
    end

    context "with 'encode_params'" do
      let(:encode_params) { true }
      context "and 'uri_encode_mode' = default (hex-normal)" do
        it "should encode special chars" do
          str = client_request.to_s
          str.should include("foo%5b%5d=bar")
          str.should include("bar=baz")
          str.should include("frobnicate=the%20froozle%3f")
        end
      end

      context "and 'uri_encode_mode' = hex-all" do
        let(:encode_mode) { 'hex-all' }
        it "should encode all chars" do
          str = client_request.to_s
          str.should include("%66%6f%6f%5b%5d=%62%61%72")
          str.should include("%62%61%72=%62%61%7a")
          str.should include("%66%72%6f%62%6e%69%63%61%74%65=%74%68%65%20%66%72%6f%6f%7a%6c%65%3f")
        end
      end

      describe "#to_s" do
        it "should produce same values if called multiple times with same options" do
          client_request.to_s.should == client_request.to_s
        end
      end

    end

  end

  describe "#set_uri" do
    it_behaves_like "with 'uri_full_url'"
    it_behaves_like "with 'uri_dir_self_reference'"
    it_behaves_like "with 'uri_dir_fake_relative'"
    it_behaves_like "with no evasions"
  end

end
