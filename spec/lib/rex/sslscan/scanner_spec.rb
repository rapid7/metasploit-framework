require 'rex/sslscan/scanner'
require 'rex/thread_factory'
require 'rex/text'
require 'rex/compat'

describe Rex::SSLScan::Scanner do

	subject{Rex::SSLScan::Scanner.new("127.0.0.1", 65535)}

	it { should respond_to :host }
	it { should respond_to :port }
	it { should respond_to :timeout }
	it { should respond_to :valid? }

	context "when validating the scanner config" do
		it "should return true when given a valid config" do
			subject.valid?.should == true
		end

		it "should return false if given an invalid host" do
			subject.host = nil
			subject.valid?.should == false
		end

		it "should return false if given an invalid port" do
			subject.port = nil
			subject.valid?.should == false
		end

		it "should return false if given an invalid timeout" do
			subject.timeout = nil
			subject.valid?.should == false
		end
	end

	context "when testing a single cipher" do
		context "an exception should be raised if" do
			it "has an invalid scanner configuration" do
				subject.host =nil
				expect{ subject.test_cipher(:SSLv2, "AES128-SHA")}.to raise_error
			end

			it "is given an invalid SSL version" do
				expect{ subject.test_cipher(:SSLv5, "AES128-SHA")}.to raise_error
			end

			it "is given an invalid cipher" do
				expect{ subject.test_cipher(:SSLv2, "FOO128-SHA")}.to raise_error
			end

			it "is given an invalid cipher for the SSL Version" do
				expect{ subject.test_cipher(:SSLv3, 'DES-CBC3-MD5')}.to raise_error
			end
		end

		# context ":rejected should be returned if" do
		# 	it "scans a non-SSL server" do
		# 		server = Rex::Socket::TcpServer.create(
		# 			'LocalHost' => '127.0.01',
		# 			'LocalPort' => 65535,
		# 			'SSL'		=> false,
		# 		)
		# 		server.start
		# 		subject.test_cipher(:SSLv2, "DES-CBC3-MD5").should == :rejected
		# 		server.stop
		# 		server.close
		# 	end

		# 	it "scans a server that doesn't support the supplied SSL version" do
		# 		server = Rex::Socket::TcpServer.create(
		# 			'LocalHost' => '127.0.01',
		# 			'LocalPort' => 65535,
		# 			'SSL'		=> true,
		# 			'SSLVersion' => :SSLv3
		# 		)
		# 		server.start
		# 		subject.test_cipher(:SSLv2, "DES-CBC3-MD5").should == :rejected
		# 		server.stop
		# 		server.close
		# 	end
		# end

		# context ":accepted should be returned if" do
		# 	it "scans a server that accepts the given cipher" do
		# 		server = Rex::Socket::TcpServer.create(
		# 			'LocalHost' => '127.0.01',
		# 			'LocalPort' => 65535,
		# 			'SSL'		=> true,
		# 			'SSLVersion' => :SSLv3,
		# 			'SSLCipher'  => 'AES256-SHA'
		# 		)
		# 		server.start
		# 		subject.test_cipher(:SSLv3, "AES256-SHA").should == :accepted
		# 		server.stop
		# 		server.close
		# 	end
		# end
	end

end