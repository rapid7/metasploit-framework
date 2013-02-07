require 'rex/sslscan/result'

describe Rex::SSLScan::Result do
	
	subject{Rex::SSLScan::Result.new}

      it { should respond_to :cert }
      it { should respond_to :sslv2 }
      it { should respond_to :sslv3 }
      it { should respond_to :tlsv1 }

	context "with no values set" do
		it "should return nil for the cert" do
			subject.cert.should == nil
		end

		it "should return an empty structure for sslv2" do
			subject.sslv2.should == {:accepted => [], :rejected => []}
		end

		it "should return an empty structure for sslv3" do
			subject.sslv3.should == {:accepted => [], :rejected => []}
		end

		it "should return an empty structure for tlsv1" do
			subject.tlsv1.should == {:accepted => [], :rejected => []}
		end

		it "should return an empty structure for #accepted" do
			subject.accepted.should == {:SSLv2=>[], :SSLv3=>[], :TLSv1=>[]}
		end

		it "should return an emtpy structure for #rejected" do
			subject.rejected.should == {:SSLv2=>[], :SSLv3=>[], :TLSv1=>[]}
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
				subject.sslv2[:accepted].should include({:cipher=>"DES-CBC3-MD5", :key_length=>168})
				subject.accepted[:SSLv2].should include({:cipher=>"DES-CBC3-MD5", :key_length=>168})
			end

			it "should add an SSLv3 cipher result to the SSLv3 Accepted array" do
				subject.add_cipher(:SSLv3, "AES256-SHA", 256, :accepted)
				subject.sslv3[:accepted].should include({:cipher=>"AES256-SHA", :key_length=>256})
				subject.accepted[:SSLv3].should include({:cipher=>"AES256-SHA", :key_length=>256})
			end

			it "should add an TLSv1 cipher result to the TLSv1 Accepted array" do
				subject.add_cipher(:TLSv1, "AES256-SHA", 256, :accepted)
				subject.tlsv1[:accepted].should include({:cipher=>"AES256-SHA", :key_length=>256})
				subject.accepted[:TLSv1].should include({:cipher=>"AES256-SHA", :key_length=>256})
			end

			it "should successfully add multiple entries in a row" do
				subject.add_cipher(:SSLv3, "AES128-SHA", 128, :accepted)
				subject.add_cipher(:SSLv3, "AES256-SHA", 256, :accepted)
				subject.sslv3[:accepted].should include({:cipher=>"AES256-SHA", :key_length=>256})
				subject.sslv3[:accepted].should include({:cipher=>"AES128-SHA", :key_length=>128})
			end
		end
		context "that was rejected" do
			it "should add an SSLv2 cipher result to the SSLv2 Rejected array" do
				subject.add_cipher(:SSLv2, "DES-CBC3-MD5", 168, :rejected)
				subject.sslv2[:rejected].should include({:cipher=>"DES-CBC3-MD5", :key_length=>168})
				subject.rejected[:SSLv2].should include({:cipher=>"DES-CBC3-MD5", :key_length=>168})
			end

			it "should add an SSLv3 cipher result to the SSLv3 Rejected array" do
				subject.add_cipher(:SSLv3, "AES256-SHA", 256, :rejected)
				subject.sslv3[:rejected].should include({:cipher=>"AES256-SHA", :key_length=>256})
				subject.rejected[:SSLv3].should include({:cipher=>"AES256-SHA", :key_length=>256})
			end

			it "should add an TLSv1 cipher result to the TLSv1 Rejected array" do
				subject.add_cipher(:TLSv1, "AES256-SHA", 256, :rejected)
				subject.tlsv1[:rejected].should include({:cipher=>"AES256-SHA", :key_length=>256})
				subject.rejected[:TLSv1].should include({:cipher=>"AES256-SHA", :key_length=>256})
			end

			it "should successfully add multiple entries in a row" do
				subject.add_cipher(:SSLv3, "AES128-SHA", 128, :rejected)
				subject.add_cipher(:SSLv3, "AES256-SHA", 256, :rejected)
				subject.sslv3[:rejected].should include({:cipher=>"AES256-SHA", :key_length=>256})
				subject.sslv3[:rejected].should include({:cipher=>"AES128-SHA", :key_length=>128})
			end
		end
	end

end