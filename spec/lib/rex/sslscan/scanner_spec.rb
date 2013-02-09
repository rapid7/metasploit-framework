require 'rex/sslscan/scanner'

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

end