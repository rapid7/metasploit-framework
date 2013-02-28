require "spec_helper"

module MetasploitDataModels
  describe Base64Serializer do
    subject{Base64Serializer.new}

    let(:test_value){{:foo => "bar", :baz => "baz"}}

    # We make it same way as in class b/c hard to keep a reliable base64
    # string literal as a fixture
    let(:base64_fixture){[Marshal.dump(test_value)].pack('m')}

    it "should turn a Hash into proper base64" do
      subject.dump(test_value).should == base64_fixture
    end

    it "should turn base64 back into a Hash" do
      subject.load(base64_fixture).should == test_value
    end
  end
end

