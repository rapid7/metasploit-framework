# -*- coding:binary -*-
require 'spec_helper'
require 'rex/proto/http/client'

# Note: Some of these tests require a failed
# connection to 127.0.0.1:1. If you have some crazy local
# firewall that is dropping packets to this, your tests
# might be slow. I wonder how Travis-CI will react to this...
describe Rex::Proto::Http::Client do

  let(:ip) { "1.2.3.4" }
  subject(:cli) do
    Rex::Proto::Http::Client.new(ip)
  end

  it "should respond to intialize" do
    cli.should be
  end

  it "should have a set of default instance variables" do
    cli.instance_variable_get(:@hostname).should == ip
    cli.instance_variable_get(:@port).should == 80
    cli.instance_variable_get(:@context).should == {}
    cli.instance_variable_get(:@ssl).should be_false
    cli.instance_variable_get(:@proxies).should be_nil
    cli.instance_variable_get(:@username).should be_empty
    cli.instance_variable_get(:@password).should be_empty
    cli.config.should be_a_kind_of Hash
  end

  it "should produce a raw HTTP request" do
    cli.request_raw.should be_a_kind_of Rex::Proto::Http::ClientRequest
  end

  it "should produce a CGI HTTP request" do
    req = cli.request_cgi
    req.should be_a_kind_of Rex::Proto::Http::ClientRequest
  end

  context "with authorization" do
    subject(:cli) do
      cli = Rex::Proto::Http::Client.new(ip)
      cli.set_config({"authorization" => "Basic base64dstuffhere"})
      cli
    end

    let(:user)   { "user" }
    let(:pass)   { "pass" }
    let(:base64) { ["user:pass"].pack('m').chomp }

    context "with credentials" do
      subject(:cli) do
        cli = Rex::Proto::Http::Client.new(ip)
        cli
      end
      let(:first_response) {
        "HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\nWWW-Authenticate: Basic realm=\"foo\"\r\n\r\n"
      }
      let(:authed_response) {
        "HTTP/1.1 200 Ok\r\nContent-Length: 0\r\n\r\n"
      }

      it "should not send creds on the first request in order to induce a 401" do
        req = cli.request_cgi
        req.to_s.should_not match("Authorization:")
      end

      it "should send creds after receiving a 401" do
        conn = double
        conn.stub(:put)
        conn.stub(:shutdown)
        conn.stub(:close)

        conn.should_receive(:get_once).and_return(first_response, authed_response)
        conn.should_receive(:put) do |str_request|
          str_request.should_not include("Authorization")
          nil
        end
        conn.should_receive(:put) do |str_request|
          str_request.should include("Authorization")
          nil
        end

        cli.should_receive(:_send_recv).twice.and_call_original

        Rex::Socket::Tcp.stub(:create).and_return(conn)

        opts = { "username" => user, "password" => pass}
        req = cli.request_cgi(opts)
        cli.send_recv(req)

        # Make sure it didn't modify the argument
        opts.should eq({ "username" => user, "password" => pass})
      end
    end

    context "and an Authorization header" do
      before do
        cli.set_config({"headers" => { "Authorization" => "Basic #{base64}" } })
      end
      it "should have one Authorization header" do
        req = cli.request_cgi
        match = req.to_s.match("Authorization: Basic")
        match.should be
        match.length.should == 1
      end
      it "should prefer the value in the header" do
        req = cli.request_cgi
        match = req.to_s.match(/Authorization: Basic (.*)$/)
        match.should be
        match.captures.length.should == 1
        match.captures[0].chomp.should == base64
      end
    end

    context "individually" do
      let(:res) do
        Rex::Proto::Http::Response.new(401, "Auth Required")
      end

      let(:opts) do
        {
          'uri'     => '/',
          'method'   => 'GET',
          'username' => user,
          'password' => pass
        }
      end

      let(:expected_response) do
        'OK'
      end

      it "should produce a basic authentication header" do
        b64 = ["#{user}:#{pass}"].pack("m*").strip
        cli.basic_auth_header(user,pass).should == "Basic #{b64}"
      end

      it "should send a request and receive a response with auth handling" do
        res.stub(:headers).and_return({'WWW-Authenticate' => ''})
        cli.stub(:_send_recv).with(an_instance_of(
          Rex::Proto::Http::ClientRequest),
          an_instance_of(Fixnum),
          an_instance_of(false.class)
        ).and_return(res)
        cli.send_auth(res, opts, 1, false).code.should eq(401)
      end

      it "should do NTLM authentication" do
        res.stub(:headers).and_return({'WWW-Authenticate' => 'NTLM'})
        cli.stub(:_send_recv).with(an_instance_of(
          Rex::Proto::Http::ClientRequest),
          an_instance_of(Fixnum)
        ).and_return(res)
        cli.send_auth(res, opts, 1, false).code.should eq(401)
      end

      context "digest" do
        def hash_to_params(h)
          params = []
          h.each {|k, v| params << "#{k}=#{v}"}
          params *= ', '
          return params
        end

        let(:digest_params) do
          {
            'username' => %Q|"#{user}"|,
            'realm'    => %Q|"admin@example.com"|,
            'qop'      => %Q|"auth"|,
            'opaque'   => %Q|"5ccc069c403ebaf9f0171e9517f40e41"|
          }
        end

        it "should do Digest authentication" do
          params = hash_to_params(digest_params)
          res.stub(:headers).and_return({'WWW-Authenticate' => %Q|Digest #{params}|})
          cli.stub(:_send_recv).with(any_args).and_return(res)
          cli.send_auth(res, opts, 1, false).code.should eq(401)
        end

        it "should set the algorithm to MD5" do
          params = hash_to_params(digest_params.merge({'algorithm'=>'MD5'}))
          res.stub(:headers).and_return({'WWW-Authenticate' => %Q|Digest #{params}|})
          cli.stub(:_send_recv).with(any_args).and_return(res)
          cli.send_auth(res, opts, 1, false).code.should eq(401)
        end

        it "should set the algorithm to SHA1" do
          params = hash_to_params(digest_params.merge({'algorithm'=>'SHA1'}))
          res.stub(:headers).and_return({'WWW-Authenticate' => %Q|Digest #{params}|})
          cli.stub(:_send_recv).with(any_args).and_return(res)
          cli.send_auth(res, opts, 1, false).code.should eq(401)
        end

        it "should set the algorithm to SHA2" do
          params = hash_to_params(digest_params.merge({'algorithm'=>'SHA2'}))
          res.stub(:headers).and_return({'WWW-Authenticate' => %Q|Digest #{params}|})
          cli.stub(:_send_recv).with(any_args).and_return(res)
          cli.send_auth(res, opts, 1, false).code.should eq(401)
        end

        it "should set the algorithm to SHA256" do
          params = hash_to_params(digest_params.merge({'algorithm'=>'SHA256'}))
          res.stub(:headers).and_return({'WWW-Authenticate' => %Q|Digest #{params}|})
          cli.stub(:_send_recv).with(any_args).and_return(res)
          cli.send_auth(res, opts, 1, false).code.should eq(401)
        end

        it "should set the algorithm to SHA384" do
          params = hash_to_params(digest_params.merge({'algorithm'=>'SHA384'}))
          res.stub(:headers).and_return({'WWW-Authenticate' => %Q|Digest #{params}|})
          cli.stub(:_send_recv).with(any_args).and_return(res)
          cli.send_auth(res, opts, 1, false).code.should eq(401)
        end

        it "should set the algorithm to SHA512" do
          params = hash_to_params(digest_params.merge({'algorithm'=>'SHA512'}))
          res.stub(:headers).and_return({'WWW-Authenticate' => %Q|Digest #{params}|})
          cli.stub(:_send_recv).with(any_args).and_return(res)
          cli.send_auth(res, opts, 1, false).code.should eq(401)
        end

        it "should set the algorithm to RMD160" do
          params = hash_to_params(digest_params.merge({'algorithm'=>'RMD160'}))
          res.stub(:headers).and_return({'WWW-Authenticate' => %Q|Digest #{params}|})
          cli.stub(:_send_recv).with(any_args).and_return(res)
          cli.send_auth(res, opts, 1, false).code.should eq(401)
        end

        it "should raise an error due to an unknown algorithm" do
          params = hash_to_params(digest_params.merge({'algorithm'=>'UNKNOWN'}))
          res.stub(:headers).and_return({'WWW-Authenticate' => %Q|Digest #{params}|})
          cli.stub(:_send_recv).with(any_args).and_return(res)
          expect { cli.send_auth(res, opts, 1, false) }.to raise_error(Exception)
        end

      end

      context "negotiate" do
        it "should do Negotiate authentication" do
          fake_challenge  = "NTLMSSP\x00\x02\x00\x00\x00"
          fake_challenge << "A" * 50
          fake_challenge[40,8] = "\x00\x00\x00\x00\x01\x00\x00\x00"
          hash = Rex::Text.encode_base64(fake_challenge)
          res.stub(:headers).and_return({'WWW-Authenticate' => "Negotiate #{hash}"})
          cli.stub(:_send_recv).with(any_args).and_return(res)
          cli.send_auth(res, opts, 1, false).code.should eq(401)
        end
      end

    end
  end

  it "should attempt to connect to a server" do
    this_cli = Rex::Proto::Http::Client.new("127.0.0.1", 1)
    expect { this_cli.connect(1) }.to raise_error ::Rex::ConnectionRefused
  end

  it "should be able to close a connection" do
    cli.close.should be_nil
  end

  it "should send a request and receive a response" do
    expected_response = 'OK'
    cli.stub(:send_request).with(an_instance_of(String), an_instance_of(Fixnum))
    res = double(Rex::Proto::Http::Response)
    res.stub(:request=)
    res.stub(:code).and_return(200)
    res.stub(:body).and_return(expected_response)
    cli.stub(:read_response).with(an_instance_of(Fixnum)).and_return(res)
    cli.send_recv('REQ').body.should eq(expected_response)
  end

  it "should send a request" do
    cli.stub(:connect).with(an_instance_of(Fixnum))
    conn = double('conn')
    conn.stub(:put).with(an_instance_of(String))
    cli.stub(:conn).and_return(conn)
    cli.send_request("req")
  end

#
# We don't even remember why this test case exists, but I'll keep this here until we find a
# a reaspon for uncomment it.
#
#  it "should test for credentials" do
#    pending "Should actually respond to :has_creds" do
#      cli.should_not have_creds
#      this_cli = described_class.new("127.0.0.1", 1, {}, false, nil, nil, "user1", "pass1" )
#      this_cli.should have_creds
#    end
#  end
#

  it "should continue to read more data if the HTTP body begins with 'HTTP'" do
    body = ''
    body << "HTTP"
    body << "A" * 10
    res = Rex::Proto::Http::Response.new(100, 'Continue')
    res.body = body
    res.stub(:parse).with(an_instance_of(String)).and_return(1)
    Rex::Proto::Http::Response.stub(:new).and_return(res)
    conn = double('conn')
    conn.stub(:get_once).with(an_instance_of(Fixnum),an_instance_of(Fixnum)).and_return('')
    cli.stub(:conn).and_return(conn)
    cli.read_response(1).body.should match(/AAAA/)
  end

  it "should end a connection with a stop" do
    cli.stop.should be_nil
  end

  it "should test if a connection is valid" do
    cli.conn?.should be_false
  end

  it "should tell if pipelining is enabled" do
    cli.should_not be_pipelining
    this_cli = Rex::Proto::Http::Client.new("127.0.0.1", 1)
    this_cli.pipeline = true
    this_cli.should be_pipelining
  end

  it "should respond to its various accessors" do
    cli.should respond_to :config
    cli.should respond_to :config_types
    cli.should respond_to :pipeline
    cli.should respond_to :local_host
    cli.should respond_to :local_port
    cli.should respond_to :conn
    cli.should respond_to :context
    cli.should respond_to :proxies
    cli.should respond_to :username
    cli.should respond_to :password
    cli.should respond_to :junk_pipeline
    # These are supposed to be protected
    cli.should respond_to :ssl
    cli.should respond_to :ssl_version
    cli.should respond_to :hostname
    cli.should respond_to :port
  end

  # Not super sure why these are protected...
  it "should refuse access to its protected accessors" do
    expect {cli.ssl}.to raise_error NoMethodError
    expect {cli.ssl_version}.to raise_error NoMethodError
    expect {cli.hostname}.to raise_error NoMethodError
    expect {cli.port}.to raise_error NoMethodError
  end

end
