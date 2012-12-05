require 'rex/post/meterpreter/packet'

describe Rex::Post::Meterpreter::Tlv do
  subject{Rex::Post::Meterpreter::Tlv.new(Rex::Post::Meterpreter::TLV_TYPE_STRING,"test")}

  it "should respond to type" do
    subject.should respond_to :type
  end

  it "should respond to value" do
    subject.should respond_to :value
  end

  it "should respond to compress" do
    subject.should respond_to :compress
  end

  it "should respond to inspect" do
    subject.should respond_to :inspect
  end

  it "should respond to meta_type?" do
    subject.should respond_to :meta_type?
  end

  it "should respond to type?" do
    subject.should respond_to :type?
  end  

  it "should respond to value?" do
    subject.should respond_to :value?
  end

  it "should respond to to_r" do
    subject.should respond_to :to_r
  end

  it "should respond to from_r" do
    subject.should respond_to :from_r
  end

  context "A String TLV" do
    it "should return the correct TLV type" do
      subject.type.should == Rex::Post::Meterpreter::TLV_TYPE_STRING
    end

    it "should return the correct value" do
      subject.value.should == "test"
    end

    context "the type? method" do
      it "should return true for STRING" do
        subject.type?(Rex::Post::Meterpreter::TLV_TYPE_STRING).should == true
      end

      it "should return false for UINT" do
        subject.type?(Rex::Post::Meterpreter::TLV_TYPE_UINT).should == false
      end
    end

    context "the value? method" do
      it "should return true for the correct value" do
        subject.value?("test").should == true
      end

      it "should return false for an incorrect value" do
        subject.value?("fake").should == false
      end
    end

    context "the inspect method" do
      it "should return a string representation of the TLV" do
        tlv_to_s = "#<Rex::Post::Meterpreter::Tlv type=STRING          meta=STRING     value=\"test\">"
        subject.inspect.should == tlv_to_s
      end
    end

    context "the to_r method" do
      it "should return the raw bytes of the TLV to send over the wire" do
        tlv_bytes = "\x00\x00\x00\r\x00\x01\x00\ntest\x00"
        subject.to_r.should == tlv_bytes
      end
    end

    context "the from_r method" do
      it "should adjust the tlv attributes from the given raw bytes" do
        subject.from_r("\x00\x00\x00\r\x00\x01\x00\ntes2\x00")
        subject.value.should == "tes2"
      end
    end
  end

  context "A Method TLV" do
    subject{Rex::Post::Meterpreter::Tlv.new(Rex::Post::Meterpreter::TLV_TYPE_METHOD,"test")}
    it "should return true when checked for a meta type of String" do
      subject.meta_type?(Rex::Post::Meterpreter::TLV_META_TYPE_STRING).should == true
    end

    it "should show the correct type and meta type in inspect" do
      tlv_to_s = "#<Rex::Post::Meterpreter::Tlv type=METHOD          meta=STRING     value=\"test\">"
      subject.inspect.should == tlv_to_s
    end
  end

  context "A String TLV with a number value" do
    subject{Rex::Post::Meterpreter::Tlv.new(Rex::Post::Meterpreter::TLV_TYPE_STRING,5)}
    it "should return the string version of the number" do
      subject.value.should == "5"
    end
  end

end

describe Rex::Post::Meterpreter::GroupTlv do
  subject{Rex::Post::Meterpreter::GroupTlv.new(Rex::Post::Meterpreter::TLV_TYPE_CHANNEL_DATA_GROUP)}

  it "should respond to tlvs" do
    subject.should respond_to :tlvs
  end

  it "should return an empty array for tlvs by default" do
    subject.tlvs.should == []
  end

  
end
