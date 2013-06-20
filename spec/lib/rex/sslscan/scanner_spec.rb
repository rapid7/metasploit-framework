# -*- coding:binary -*-
require 'rex/sslscan/scanner'
require 'rex/thread_factory'
require 'rex/text'
require 'rex/compat'

describe Rex::SSLScan::Scanner do

	subject{Rex::SSLScan::Scanner.new("google.com", 443)}

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

		context ":rejected should be returned if" do
			it "scans a server that doesn't support the supplied SSL version" do
				subject.test_cipher(:SSLv3, "DES-CBC-SHA").should == :rejected
			end

			it "scans a server that doesn't support the cipher" do
				subject.test_cipher(:SSLv3, "DHE-DSS-AES256-SHA").should == :rejected
			end
		end

		context ":accepted should be returned if" do
			it "scans a server that accepts the given cipher" do
				subject.test_cipher(:SSLv3, "AES256-SHA").should == :accepted
			end
		end
	end

	context "when retrieving the cert" do
		it "should return nil if it can't connect" do
			subject.get_cert(:SSLv3, "DES-CBC-SHA").should == nil
		end

		it "should return an X509 cert if it can connect" do
			subject.get_cert(:SSLv3, "AES256-SHA").class.should == OpenSSL::X509::Certificate
		end
	end

	context "when scanning https://google.com" do
		it "should return a Result object" do
			result = subject.scan
			result.class.should == Rex::SSLScan::Result
		end

		context "if SSLv2 is not available locally" do
			before(:each) do
				subject.stub(:check_opensslv2).and_return(false)
				subject.send(:initialize, 'google.com', 443)
			end
			it "should mark SSLv2 as unsupported" do
				subject.supported_versions.should_not include :SSLv2
				subject.sslv2.should == false
			end

			it "should not test any SSLv2 ciphers" do
				res = subject.scan
				res.sslv2.should == []
			end
		end
	end

end
