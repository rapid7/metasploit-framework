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

	before(:all) do
		@ip = "1.2.3.4"
		@cli = Rex::Proto::Http::Client.new(@ip)
	end

	it "should respond to intialize" do
		@cli.should be
	end

	it "should have a set of default instance variables" do
		@cli.instance_variable_get(:@hostname).should == @ip
		@cli.instance_variable_get(:@port).should == 80
		@cli.instance_variable_get(:@context).should == {}
		@cli.instance_variable_get(:@ssl).should be_false
		@cli.instance_variable_get(:@proxies).should be_nil
		# @cli.instance_variable_get(:@username).should be_empty
		# @cli.instance_variable_get(:@password).should be_empty
		@cli.config.should be_a_kind_of Hash
		@cli.config_types.should be_a_kind_of Hash
	end

	it "should produce a raw HTTP request", :pending => "Waiting for PR #1500" do
		@cli.request_raw.should be_a_kind_of Rex::Proto::Http::Request
	end

	it "should produce a CGI HTTP request", :pending => "Waiting for PR #1500" do
		@cli.request_cgi.should be_a_kind_of Rex::Proto::Http::Request
	end

	it "should attempt to connect to a server" do
		this_cli = Rex::Proto::Http::Client.new("127.0.0.1", 1)
		expect { this_cli.connect(1) }.to raise_error ::Rex::ConnectionRefused
	end

	it "should be able to close a connection" do
		@cli.close.should be_nil
	end

	it "should send a request and receive a response", :pending => excuse_needs_connection do

	end

	it "should send a request and receive a response without auth handling", :pending => excuse_needs_connection do

	end

	it "should send a request", :pending => excuse_needs_connection do

	end

	it "should test for credentials" do
		# @cli.should_not have_creds
		# this_cli = Rex::Proto::Http::Client.new("127.0.0.1", 1, {}, false, nil, nil, "user1", "pass1" )
		# this_cli.should have_creds
		pending "Should actually respond to :has_creds"
	end

	it "should send authentication", :pending => excuse_needs_connection

	it "should produce a basic authentication header", :pending => "Waiting for #1500" do
		u = "user1"
		p = "pass1"
		b64 = ["#{u}:#{p}"].pack("m*").strip
		@cli.basic_auth_header("user1","pass1").should == "Basic #{b64}"
	end

	it "should perform digest authentication", :pending => excuse_needs_auth do

	end

	it "should perform negotiate authentication", :pending => excuse_needs_auth do

	end

	it "should get a response", :pending => excuse_needs_connection do

	end

	it "should end a connection with a stop" do
		@cli.stop.should be_nil
	end

	it "should test if a connection is valid" do
		@cli.conn?.should be_false
	end

	it "should tell if pipelining is enabled" do
		@cli.pipelining?.should be_false
		this_cli = Rex::Proto::Http::Client.new("127.0.0.1", 1)
		this_cli.pipeline = true
		this_cli.pipelining?.should be_true
	end

	it "should return an encoded URI", :pending => excuse_lazy(:set_encode_uri) do

	end

	it "should return an encoded query string", :pending => excuse_lazy(:set_encode_qa) do

	end

	# These set_ methods all exercise the evasion opts, looks like

	it "should set and return the URI", :pending => excuse_lazy(:set_uri) do
		
	end

	it "should set and return the CGI", :pending => excuse_lazy(:set_cgi) do

	end

	it "should set and return the HTTP verb", :pending => excuse_lazy(:set_method) do

	end

	it "should set and return the version string", :pending => excuse_lazy(:set_version) do

	end

	it "should set and return the HTTP seperator and body string", :pending => excuse_lazy(:set_body) do

	end

	it "should set and return the path", :pending => excuse_lazy(:set_path_info) do

	end

	it "should set and return the whitespace between method and URI", :pending => excuse_lazy(:set_method_uri_spacer) do

	end

	it "should set and return the whitespace between the version and URI", :pending => excuse_lazy(:set_uri_version_spacer) do

	end

	it "should set and return padding before the URI", :pending => excuse_lazy(:set_uri_prepend) do

	end

	it "should set and return padding after the URI" do
		@cli.set_uri_append.should be_empty
	end

	it "should set and return the host header", :pending => excuse_lazy(:set_host_header) do

	end

	it "should set and return the agent header", :pending => excuse_lazy(:set_agent_header) do

	end

	it "should set and return the cookie header", :pending => excuse_lazy(:set_cookie_header) do

	end

	it "should set and return the content-type header", :pending => excuse_lazy(:set_cookie_header) do

	end

	it "should set and return the content-length header", :pending => excuse_lazy(:set_content_len_header) do

	end

	it "should set and return the basic authentication header", :pending => excuse_lazy(:set_basic_auth_header) do

	end

	it "should set and return any extra headers", :pending => excuse_lazy(:set_extra_headers) do

	end

	it "should set the chunked encoding header", :pending => excuse_lazy(:set_chunked_header) do

	end

	it "should set and return raw_headers", :pending => "#set_raw_headers() doesn't seem to actually do anything" do

	end

	it "should set and return a formatted header", :pending => excuse_lazy(:set_formatted_header) do

	end

	it "should respond to its various accessors" do
		@cli.should respond_to :config
		@cli.should respond_to :config_types
		@cli.should respond_to :pipeline
		@cli.should respond_to :local_host
		@cli.should respond_to :local_port
		@cli.should respond_to :conn
		@cli.should respond_to :context
		@cli.should respond_to :proxies
		# @cli.should respond_to :username
		# @cli.should respond_to :password
		@cli.should respond_to :junk_pipeline
		# These are supposed to be protected
		@cli.should respond_to :ssl
		@cli.should respond_to :ssl_version
		@cli.should respond_to :hostname
		@cli.should respond_to :port
	end

	# Not super sure why these are protected...
	it "should refuse access to its protected accessors" do
		expect {@cli.ssl}.to raise_error NoMethodError
		expect {@cli.ssl_version}.to raise_error NoMethodError
		expect {@cli.hostname}.to raise_error NoMethodError
		expect {@cli.port}.to raise_error NoMethodError
	end

end
