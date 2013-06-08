# -*- coding:binary -*-
require 'rex/proto/http/client'

# Note: Some of these tests require a failed
# connection to 127.0.0.1:1. If you have some crazy local
# firewall that is dropping packets to this, your tests
# might be slow. I wonder how Travis-CI will react to this...
describe Rex::Proto::Http::Client do

	class << self

		# Set a standard excuse that indicates that the method
		# under test needs to be first examined to figure out
		# what's sane and what's not.
		def excuse_lazy(test_method=nil)
			ret = "need to determine pass/fail criteria"
			test_method ? ret << " for #{test_method.inspect}" : ret
		end

		# Complain about not having a "real" connection (can be mocked)
		def excuse_needs_connection
			"need to actually set up an HTTP server to test"
		end

		# Complain about not having a real auth server (can be mocked)
		def excuse_needs_auth
			"need to set up an HTTP authentication challenger"
		end

	end

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
	end

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
		let(:user) { "user" }
		let(:pass) { "pass" }

		it "should not send creds on the first request in order to induce a 401" do
			req = cli.request_cgi
			req.to_s.should_not match("Authorization:")
		end

		it "should send creds after receiving a 401" do
			conn = mock
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
			opts.should == { "username" => user, "password" => pass}
		end

	end

	it "should attempt to connect to a server" do
		this_cli = Rex::Proto::Http::Client.new("127.0.0.1", 1)
		expect { this_cli.connect(1) }.to raise_error ::Rex::ConnectionRefused
	end

	it "should be able to close a connection" do
		cli.close.should be_nil
	end

	it "should send a request and receive a response", :pending => excuse_needs_connection do

	end

	it "should send a request and receive a response without auth handling", :pending => excuse_needs_connection do

	end

	it "should send a request", :pending => excuse_needs_connection do

	end

	it "should test for credentials" do
		pending "Should actually respond to :has_creds" do
			cli.should_not have_creds
			this_cli = described_class.new("127.0.0.1", 1, {}, false, nil, nil, "user1", "pass1" )
			this_cli.should have_creds
		end
	end

	it "should send authentication", :pending => excuse_needs_connection

	it "should produce a basic authentication header" do
		u = "user1"
		p = "pass1"
		b64 = ["#{u}:#{p}"].pack("m*").strip
		cli.basic_auth_header("user1","pass1").should == "Basic #{b64}"
	end

	it "should perform digest authentication", :pending => excuse_needs_auth do

	end

	it "should perform negotiate authentication", :pending => excuse_needs_auth do

	end

	it "should get a response", :pending => excuse_needs_connection do

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
