require 'spec_helper'
 
require 'rex/proto/http/client_request'
 
shared_context "with 'uri_dir_self_reference'" do
  before(:all) do
    client_request.config['uri_dir_self_reference'] = true
  end
 
  describe "#set_uri" do
    it "should return the unmodified uri" do
      client_request.send(:set_uri).should == "/./"
    end
  end
end
 
shared_context "with no evasions" do
  before(:all) do
    client_request.config['uri_dir_self_reference'] = false
    client_request.config['uri_fake_params_start'] = false
    client_request.config['uri_full_url'] = false
  end
 
  describe "#set_uri" do
    it "should return the unmodified uri" do
      client_request.send(:set_uri).should == "/"
    end
  end
end
 
shared_context "with 'uri_full_url'" do
 
  before(:all) do
    client_request.config['uri_full_url'] = true
  end
 
  before(:each) do
    client_request.config['vhost'] = host
  end
 
  context "with ipv4 host" do
    let(:host) { '192.0.2.1' }
    
    it_behaves_like "uri_full_url"
  end
  
  context "with ipv6 host" do
    let(:host) { '2001:DB8::1' }
    #before(:each) do
    # client_request.config['vhost'] = "[#{host}]"
    #end
    
    it_behaves_like "uri_full_url"
  end
  
  context "with dns host" do
    let(:host) { 'www.example.com' }
    
    it_behaves_like "uri_full_url"
  end
 
end
 
shared_examples "uri_full_url" do
  
  it "should have the host in the URI" do
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
        # Yes, vhost is in the config. There is no godly reason why this
        # should be so. 
        'client_config' => { 'vhost' => 'www.example.com', },
      }),
      { 
        :set_cgi               => { :result => "/" },
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
        'client_config' => { 'header_folding' => true, }
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
        'client_config' => { 'vhost' => "2001:DB8::1" },
      }),
      { 
        :set_host_header       => { :result => "Host: [2001:DB8::1]\r\n" },
      }
    ],
    
    [ "with ipv6 host and non-default port",
      default_options.merge({
        'port' => 1234, 
        'client_config' => { 'vhost' => "2001:DB8::1" },
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
        'vars_get' => {
          'foo[]' => 'bar',
          'foo[]' => 'baz', 
        }
      })
      Rex::Proto::Http::ClientRequest.new(options_with_params)
    }
  end
 
  describe "#set_uri" do
    it_behaves_like "with 'uri_full_url'"
    it_behaves_like "with 'uri_dir_self_reference'"
    it_behaves_like "with no evasions"
  end
 
end