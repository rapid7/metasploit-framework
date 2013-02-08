require 'rex/sslscan/result'

describe Rex::SSLScan::Result do
	
	subject{Rex::SSLScan::Result.new}

      it { should respond_to :cert }
      it { should respond_to :ciphers }

	context "with no values set" do
		it "should return nil for the cert" do
			subject.cert.should == nil
		end

		it "should return an empty array for ciphers" do
			subject.ciphers.should == []
		end

		it "should return an empty array for accepted" do
			subject.accepted.should == []
		end

		it "should return an empty array for rejected" do
			subject.rejected.should == []
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

	context "adding a cipher result" do
		context "should raise an exception if" do
			it "given an invalid SSL version" do
				expect{subject.add_cipher(:ssl3, 'AES256-SHA', 256, :accepted )}.to raise_error
			end
				
			it "given SSL version as a string" do
				expect{subject.add_cipher('sslv3', 'AES256-SHA', 256, :accepted )}.to raise_error
			end

			it "given an invalid SSL cipher" do
				expect{subject.add_cipher(:SSLv3, 'FOO256-SHA', 256, :accepted )}.to raise_error
			end

			it "given an unsupported cipher for the version" do
				expect{subject.add_cipher(:SSLv3, 'DES-CBC3-MD5', 256, :accepted )}.to raise_error
			end

			it "given a non-number for key length" do
				expect{subject.add_cipher(:SSLv3, 'AES256-SHA', "256", :accepted )}.to raise_error
			end

			it "given a decimal key length" do
				expect{subject.add_cipher(:SSLv3, 'AES256-SHA', 25.6, :accepted )}.to raise_error
			end

			it "given an invalid status" do
				expect{subject.add_cipher(:SSLv3, 'AES256-SHA', 256, :good )}.to raise_error
			end

			it "given status as a string" do
				expect{subject.add_cipher(:SSLv3, 'AES256-SHA', 256, "accepted" )}.to raise_error
			end
		end
		context "that was accepted" do
			it "should add an SSLv2 cipher result to the SSLv2 Accepted array" do
				subject.add_cipher(:SSLv2, "DES-CBC3-MD5", 168, :accepted)
				subject.accepted(:SSLv2).should include({
					:version => :SSLv2, 
					:cipher=>"DES-CBC3-MD5", 
					:key_length=>168, 
					:weak=> false, 
					:status => :accepted}) 
			end

			it "should add an SSLv3 cipher result to the SSLv3 Accepted array" do
				subject.add_cipher(:SSLv3, "AES256-SHA", 256, :accepted)
				subject.accepted(:SSLv3).should include({
					:version => :SSLv3, 
					:cipher=>"AES256-SHA", 
					:key_length=>256, 
					:weak=> false, 
					:status => :accepted})
			end

			it "should add an TLSv1 cipher result to the TLSv1 Accepted array" do
				subject.add_cipher(:TLSv1, "AES256-SHA", 256, :accepted)
				subject.accepted(:TLSv1).should include({
					:version => :TLSv1, 
					:cipher=>"AES256-SHA", 
					:key_length=>256, 
					:weak=> false, 
					:status => :accepted})
			end

			it "should successfully add multiple entries in a row" do
				subject.add_cipher(:SSLv3, "AES128-SHA", 128, :accepted)
				subject.add_cipher(:SSLv3, "AES256-SHA", 256, :accepted)
				subject.accepted(:SSLv3).should include({
					:version => :SSLv3, 
					:cipher=>"AES256-SHA", 
					:key_length=>256, 
					:weak=> false, 
					:status => :accepted})
				subject.accepted(:SSLv3).should include({
					:version => :SSLv3, 
					:cipher=>"AES256-SHA", 
					:key_length=>256, 
					:weak=> false, 
					:status => :accepted})
			end

			it "should not add duplicate entries" do
				subject.add_cipher(:SSLv3, "AES128-SHA", 128, :accepted)
				subject.add_cipher(:SSLv3, "AES128-SHA", 128, :accepted)
				subject.accepted(:SSLv3).count.should == 1
			end
		end
		context "that was rejected" do
			it "should add an SSLv2 cipher result to the SSLv2 Rejected array" do
				subject.add_cipher(:SSLv2, "DES-CBC3-MD5", 168, :rejected)
				subject.rejected(:SSLv2).should include({
					:version => :SSLv2, 
					:cipher=>"DES-CBC3-MD5", 
					:key_length=>168, 
					:weak=> false, 
					:status => :rejected}) 
			end

			it "should add an SSLv3 cipher result to the SSLv3 Rejected array" do
				subject.add_cipher(:SSLv3, "AES256-SHA", 256, :rejected)
				subject.rejected(:SSLv3).should include({
					:version => :SSLv3, 
					:cipher=>"AES256-SHA", 
					:key_length=>256, 
					:weak=> false, 
					:status => :rejected})
			end

			it "should add an TLSv1 cipher result to the TLSv1 Rejected array" do
				subject.add_cipher(:TLSv1, "AES256-SHA", 256, :rejected)
				subject.rejected(:TLSv1).should include({
					:version => :TLSv1, 
					:cipher=>"AES256-SHA", 
					:key_length=>256, 
					:weak=> false, 
					:status => :rejected})
			end

			it "should successfully add multiple entries in a row" do
				subject.add_cipher(:SSLv3, "AES128-SHA", 128, :rejected)
				subject.add_cipher(:SSLv3, "AES256-SHA", 256, :rejected)
				subject.rejected(:SSLv3).should include({
					:version => :SSLv3, 
					:cipher=>"AES256-SHA", 
					:key_length=>256, 
					:weak=> false, 
					:status => :rejected})
				subject.rejected(:SSLv3).should include({
					:version => :SSLv3, 
					:cipher=>"AES128-SHA", 
					:key_length=>128, 
					:weak=> false, 
					:status => :rejected})
			end

			it "should not add duplicate entries" do
				subject.add_cipher(:SSLv3, "AES128-SHA", 128, :rejected)
				subject.add_cipher(:SSLv3, "AES128-SHA", 128, :rejected)
				subject.rejected(:SSLv3).count.should == 1
			end
		end
	end

	context "enumerating all accepted ciphers" do
		before(:each) do
			subject.add_cipher(:SSLv2, "DES-CBC3-MD5", 168, :accepted)
			subject.add_cipher(:SSLv3, "AES256-SHA", 256, :accepted)
			subject.add_cipher(:TLSv1, "AES256-SHA", 256, :accepted)
			subject.add_cipher(:SSLv3, "AES128-SHA", 128, :accepted)
		end

		it "should return an array of cipher detail hashes" do
			subject.each_accepted do |cipher_details|
				cipher_details.should include(:version, :cipher, :key_length, :status, :weak)
			end
		end

		it "should return all of the accepted cipher details" do
			count = 0
			subject.each_accepted do |cipher_details|
				count = count+1
			end
			count.should == 4
		end
	end

	context "enumerating all rejected ciphers" do
		before(:each) do
			subject.add_cipher(:SSLv2, "DES-CBC3-MD5", 168, :rejected)
			subject.add_cipher(:SSLv3, "AES256-SHA", 256, :rejected)
			subject.add_cipher(:TLSv1, "AES256-SHA", 256, :rejected)
			subject.add_cipher(:SSLv3, "AES128-SHA", 128, :rejected)
		end

		it "should return an array of cipher detail hashes" do
			subject.each_rejected do |cipher_details|
				cipher_details.should include(:version, :cipher, :key_length, :status, :weak)
			end
		end

		it "should return all of the rejected cipher details" do
			count = 0
			subject.each_rejected do |cipher_details|
				count = count+1
			end
			count.should == 4
		end
	end

	context "checking SSL support" do
		context "for SSLv2" do
			it "should return false if there are no accepted ciphers" do
				subject.supports_sslv2?.should == false
			end
			it "should return true if there are accepted ciphers" do
				subject.add_cipher(:SSLv2, "DES-CBC3-MD5", 168, :accepted)
				subject.supports_sslv2?.should == true
			end
		end
		context "for SSLv3" do
			it "should return false if there are no accepted ciphers" do
				subject.supports_sslv3?.should == false
			end
			it "should return true if there are accepted ciphers" do
				subject.add_cipher(:SSLv3, "AES256-SHA", 256, :accepted)
				subject.supports_sslv3?.should == true
			end
		end
		context "for TLSv1" do
			it "should return false if there are no accepted ciphers" do
				subject.supports_tlsv1?.should == false
			end
			it "should return true if there are accepted ciphers" do
				subject.add_cipher(:TLSv1, "AES256-SHA", 256, :accepted)
				subject.supports_tlsv1?.should == true
			end
		end
		context "for SSL at large" do
			it "should return false if there are no accepted ciphers" do
				subject.supports_ssl?.should == false
			end
			it "should return true if there are accepted ciphers" do
				subject.add_cipher(:TLSv1, "AES256-SHA", 256, :accepted)
				subject.supports_ssl?.should == true
			end
		end
	end

end