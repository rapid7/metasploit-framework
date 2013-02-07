require 'rex/sslscan/result'

describe Rex::SSLScan::Result do
	
	subject{Rex::SSLScan::Result.new}

	it "should respond to cert" do
		subject.should respond_to :cert
	end

	it "should respond to sslv2" do
		subject.should respond_to :sslv2
	end

	it "should respond to sslv3" do
		subject.should respond_to :sslv3
	end

	it "should respond to tlsv1" do
		subject.should respond_to :tlsv1
	end

	context "with no values set" do
		it "should return nil for the cert" do
			subject.cert.should == nil
		end

		it "should return an empty hash for sslv2" do
			subject.sslv2.should == {}
		end

		it "should return an empty hash for sslv3" do
			subject.sslv3.should == {}
		end

		it "should return an empty hash for tlsv1" do
			subject.tlsv1.should == {}
		end
	end

	context "setting the cert" do
		it "should accept nil" do
			subject.cert = nil
			subject.cert.should == nil
		end

		it "should accept an X509 cert" do
			cert = OpenSSL::X509::Certificate.new
			subject.cert = cert
			subject.cert.should == cert
		end

		it "should raise an exception for anything else" do
			expect{subject.cert = "foo"}.to raise_error
		end
	end



end