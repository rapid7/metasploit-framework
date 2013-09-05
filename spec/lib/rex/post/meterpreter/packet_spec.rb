# -*- coding:binary -*-
require 'rex/post/meterpreter/packet'

describe Rex::Post::Meterpreter::Tlv do
  subject(:tlv) {
    Rex::Post::Meterpreter::Tlv.new(
      Rex::Post::Meterpreter::TLV_TYPE_STRING,
      "test"
    )
  }

  it "should respond to type" do
    tlv.should respond_to :type
  end

  it "should respond to value" do
    tlv.should respond_to :value
  end

  it "should respond to compress" do
    tlv.should respond_to :compress
  end

  it "should respond to inspect" do
    tlv.should respond_to :inspect
  end

  it "should respond to meta_type?" do
    tlv.should respond_to :meta_type?
  end

  it "should respond to type?" do
    tlv.should respond_to :type?
  end

  it "should respond to value?" do
    tlv.should respond_to :value?
  end

  it "should respond to to_r" do
    tlv.should respond_to :to_r
  end

  it "should respond to from_r" do
    tlv.should respond_to :from_r
  end

  context "A String TLV" do
    it "should return the correct TLV type" do
      tlv.type.should == Rex::Post::Meterpreter::TLV_TYPE_STRING
    end

    it "should return the correct value" do
      tlv.value.should == "test"
    end

    context "#type?" do
      it "should return true for STRING" do
        tlv.type?(Rex::Post::Meterpreter::TLV_TYPE_STRING).should == true
      end

      it "should return false for UINT" do
        tlv.type?(Rex::Post::Meterpreter::TLV_TYPE_UINT).should == false
      end
    end

    context "#value?" do
      it "should return true for the correct value" do
        tlv.value?("test").should == true
      end

      it "should return false for an incorrect value" do
        tlv.value?("fake").should == false
      end
    end

    context "#inspect" do
      it "should return a string representation of the TLV" do
        tlv_to_s = "#<Rex::Post::Meterpreter::Tlv type=STRING          meta=STRING     value=\"test\">"
        tlv.inspect.should == tlv_to_s
      end
    end

    context "#to_r" do
      it "should return the raw bytes of the TLV to send over the wire" do
        tlv_bytes = "\x00\x00\x00\r\x00\x01\x00\ntest\x00"
        tlv.to_r.should == tlv_bytes
      end
    end

    context "#from_r" do
      it "should adjust the tlv attributes from the given raw bytes" do
        tlv.from_r("\x00\x00\x00\r\x00\x01\x00\ntes2\x00")
        tlv.value.should == "tes2"
      end
    end
  end

  context "A Method TLV" do
    subject(:tlv) {
      Rex::Post::Meterpreter::Tlv.new(
        Rex::Post::Meterpreter::TLV_TYPE_METHOD,
        "test"
      )
    }
    it "should have a meta type of String" do
      tlv.meta_type?(Rex::Post::Meterpreter::TLV_META_TYPE_STRING).should == true
    end

    it "should show the correct type and meta type in inspect" do
      tlv_to_s = "#<Rex::Post::Meterpreter::Tlv type=METHOD          meta=STRING     value=\"test\">"
      tlv.inspect.should == tlv_to_s
    end
  end

  context "A String TLV with a number value" do
    subject(:tlv) {
      Rex::Post::Meterpreter::Tlv.new(Rex::Post::Meterpreter::TLV_TYPE_STRING,5)
    }
    it "should return the string version of the number" do
      tlv.value.should == "5"
    end
  end

end

describe Rex::Post::Meterpreter::GroupTlv do
  subject(:group_tlv) {
    Rex::Post::Meterpreter::GroupTlv.new(
      Rex::Post::Meterpreter::TLV_TYPE_CHANNEL_DATA_GROUP
    )
  }

  it "should respond to tlvs" do
    group_tlv.should respond_to :tlvs
  end

  it "should respond to each" do
    group_tlv.should respond_to :each
  end

  it "should respond to each_tlv" do
    group_tlv.should respond_to :each_tlv
  end

  it "should respond to each_with_index" do
    group_tlv.should respond_to :each_with_index
  end

  it "should respond to each_tlv_with_index" do
    group_tlv.should respond_to :each_tlv_with_index
  end

  it "should respond to get_tlvs" do
    group_tlv.should respond_to :get_tlvs
  end

  it "should respond to add_tlv" do
    group_tlv.should respond_to :add_tlv
  end

  it "should respond to add_tlvs" do
    group_tlv.should respond_to :add_tlvs
  end

  it "should respond to get_tlv" do
    group_tlv.should respond_to :get_tlv
  end

  it "should respond to get_tlv_value" do
    group_tlv.should respond_to :get_tlv_value
  end

  it "should respond to get_tlv_values" do
    group_tlv.should respond_to :get_tlv_values
  end

  it "should respond to has_tlv?" do
    group_tlv.should respond_to :has_tlv?
  end

  it "should respond to reset" do
    group_tlv.should respond_to :reset
  end

  it "should respond to to_r" do
    group_tlv.should respond_to :to_r
  end

  it "should respond to from_r" do
    group_tlv.should respond_to :from_r
  end

  it "should return an empty array for tlvs by default" do
    group_tlv.tlvs.should == []
  end

  context "#add_tlv" do
    it "should add to the tlvs array when given basic tlv paramaters" do
      group_tlv.add_tlv(Rex::Post::Meterpreter::TLV_TYPE_STRING,"test")
      group_tlv.tlvs.first.type.should == Rex::Post::Meterpreter::TLV_TYPE_STRING
      group_tlv.tlvs.first.value.should == "test"
    end

    it  "should replace any existing TLV of the same type when the replace flag is set to true" do
      group_tlv.add_tlv(Rex::Post::Meterpreter::TLV_TYPE_STRING,"test")
      group_tlv.add_tlv(Rex::Post::Meterpreter::TLV_TYPE_STRING,"test2", true)
      group_tlv.tlvs.count.should == 1
      group_tlv.tlvs.first.value.should == "test2"
    end

    it "should add both if replace is set to false" do
      group_tlv.add_tlv(Rex::Post::Meterpreter::TLV_TYPE_STRING,"test")
      group_tlv.add_tlv(Rex::Post::Meterpreter::TLV_TYPE_STRING,"test2", false)
      group_tlv.tlvs.first.value.should == "test"
      group_tlv.tlvs.last.value.should == "test2"
    end
  end

  context "#add_tlvs" do
    it "should be able to add an array of type-value hashes" do
      tlv_array = [
        {'type' => Rex::Post::Meterpreter::TLV_TYPE_STRING, 'value' => "test"},
        {'type' => Rex::Post::Meterpreter::TLV_TYPE_STRING, 'value' => "test2"}
      ]
      group_tlv.add_tlvs(tlv_array)
      group_tlv.tlvs.count.should == 2
      group_tlv.tlvs.first.value.should == "test"
      group_tlv.tlvs.last.value.should == "test2"
    end

    it "should raise an error when given something other than nil or an array" do
      pending "RM #7598"
      group_tlv.add_tlvs("bad value").should raise_error
    end

    it "should raise an error when given an array of objects other than hashes" do
      pending "RM #7598"
      group_tlv.add_tlvs([1,2,3]).should raise_error
    end

    it "should raise an error when any of the hashes are missing a key" do
      pending "RM #7598"
      tlv_array = [
        {:type => Rex::Post::Meterpreter::TLV_TYPE_STRING, :value => "test"},
        {:type => Rex::Post::Meterpreter::TLV_TYPE_STRING}
      ]
      group_tlv.add_tlvs(tlv_array).should raise_error
    end
  end

  context "with TLVs added" do
    before(:each) do
      group_tlv.reset
      tlv_array = [
        {'type' => Rex::Post::Meterpreter::TLV_TYPE_STRING, 'value' => "test"},
        {'type' => Rex::Post::Meterpreter::TLV_TYPE_STRING, 'value' => "test2"},
        {'type' => Rex::Post::Meterpreter::TLV_TYPE_UINT, 'value' => 5}
      ]
      group_tlv.add_tlvs(tlv_array)
      @raw_group =  "\x00\x00\x00/@\x00\x005\x00\x00\x00\r\x00\x01\x00\ntest\x00\x00\x00\x00\x0E\x00\x01\x00\ntest2\x00\x00\x00\x00\f\x00\x02\x00\v\x00\x00\x00\x05"
    end

    it "should empty the array of TLV when reset is called" do
      group_tlv.reset
      group_tlv.tlvs.should == []
    end

    it "should convert to raw bytes when to_r is called" do
      group_tlv.to_r.should == @raw_group
    end


    context "#from_r" do
      it "should build the TLV group when given the propper raw bytes" do
        group_tlv.reset
        group_tlv.from_r( @raw_group)
        group_tlv.tlvs[0].inspect.should == "#<Rex::Post::Meterpreter::Tlv type=STRING          meta=STRING     value=\"test\">"
        group_tlv.tlvs[1].inspect.should == "#<Rex::Post::Meterpreter::Tlv type=STRING          meta=STRING     value=\"test2\">"
        group_tlv.tlvs[2].inspect.should == "#<Rex::Post::Meterpreter::Tlv type=UINT            meta=INT        value=5>"
      end
    end


    context "#get_tlvs" do
      it "should return all TLVs of the supplied type" do
        tlvs = group_tlv.get_tlvs(Rex::Post::Meterpreter::TLV_TYPE_STRING)
        tlvs.count.should == 2
        tlvs.first.value.should == "test"
        tlvs.last.value.should == "test2"
      end

      it "should return all TLVs when supplied the ANY TLV type" do
        tlvs = group_tlv.get_tlvs(Rex::Post::Meterpreter::TLV_TYPE_ANY)
        tlvs.count.should == group_tlv.tlvs.count
      end

      it "should return an empty array for a TLV type that isn't present" do
        group_tlv.get_tlvs(Rex::Post::Meterpreter::TLV_TYPE_BOOL).should == []
      end

      it "should return an empty array for a nonexistant TLV type" do
        group_tlv.get_tlvs(55555555).should == []
      end
    end

    context "#get_tlv" do
      it "should return the first TLV of the specified type by default" do
        group_tlv.get_tlv(Rex::Post::Meterpreter::TLV_TYPE_STRING).should == group_tlv.tlvs.first
        group_tlv.get_tlv(Rex::Post::Meterpreter::TLV_TYPE_UINT).should == group_tlv.tlvs.last
      end

      it "should return the correct TLV of the specified type for the given index" do
        group_tlv.get_tlv(Rex::Post::Meterpreter::TLV_TYPE_STRING,1).should == group_tlv.tlvs[1]
      end

      it "should return nil if given an out of bounds index" do
        group_tlv.get_tlv(Rex::Post::Meterpreter::TLV_TYPE_STRING,5).should == nil
      end

      it "should return nil if given a non-present TLV type" do
        group_tlv.get_tlv(Rex::Post::Meterpreter::TLV_TYPE_BOOL).should == nil
      end
    end

    context "#get_tlv_value" do
      it "should return the value of the first TLV with the given type" do
        group_tlv.get_tlv_value(Rex::Post::Meterpreter::TLV_TYPE_STRING).should == group_tlv.tlvs.first.value
      end

      it "should return the correct TLV value of the specified type for the given index" do
        group_tlv.get_tlv_value(Rex::Post::Meterpreter::TLV_TYPE_STRING,1).should == group_tlv.tlvs[1].value
      end

      it "should return nil if given an out of bounds index" do
        group_tlv.get_tlv_value(Rex::Post::Meterpreter::TLV_TYPE_STRING,5).should == nil
      end

      it "should return nil if given a non-present TLV type" do
        group_tlv.get_tlv_value(Rex::Post::Meterpreter::TLV_TYPE_BOOL).should == nil
      end
    end

    context "#get_tlv_values" do
      it "should return an array of values for the designated TLV types" do
        group_tlv.get_tlv_values(Rex::Post::Meterpreter::TLV_TYPE_STRING).should == ["test", "test2"]
      end

      it "should return an empty array for a non-present TLV type" do
        group_tlv.get_tlv_values(Rex::Post::Meterpreter::TLV_TYPE_BOOL).should == []
      end
    end

    context "#has_tlv?" do
      it "should return true if the TLV Type is present" do
        group_tlv.has_tlv?(Rex::Post::Meterpreter::TLV_TYPE_STRING).should == true
      end

      it "should return false if the TLV type is not present" do
        group_tlv.has_tlv?(Rex::Post::Meterpreter::TLV_TYPE_BOOL).should == false
      end
    end
  end
end

describe Rex::Post::Meterpreter::Packet do
  context "Request Packet" do
    subject(:packet) {
      Rex::Post::Meterpreter::Packet.new(
        Rex::Post::Meterpreter::PACKET_TYPE_REQUEST,
        "test_method"
      )
    }

    it "should respond to created_at" do
      packet.should respond_to :created_at
    end

    it "should respond to response?" do
      packet.should respond_to :response?
    end

    it "should respond to method?" do
      packet.should respond_to :method?
    end

    it "should respond to method" do
      packet.should respond_to :method
    end

    it "should respond to result?" do
      packet.should respond_to :result?
    end

    it "should respond to result=" do
      packet.should respond_to :result=
    end

    it "should respond to result" do
      packet.should respond_to :result
    end

    it "should respond to rid" do
      packet.should respond_to :rid
    end

    it "should return false for response?" do
      packet.response?.should == false
    end

    it "should evaluate the method correctly" do
      packet.method?("test_method").should == true
      packet.method?("blah").should == false
    end

    it "should accept new methods" do
      packet.method= "test_method2"
      packet.method?("test_method2").should == true
    end

    it "should return the correct method" do
      packet.method.should == "test_method"
    end

    it "should not have a result" do
      packet.result.should == nil
    end

    it "should return a valid request id" do
      packet.rid.should =~ /\A\d{32}\Z/
    end

    it "should be created when Packet.create_request is called" do
      req = Rex::Post::Meterpreter::Packet.create_request("test_method")
      req.class.should == Rex::Post::Meterpreter::Packet
      req.response?.should == false
      req.method?("test_method").should == true
    end

    it "should return the correct raw byte form of the packet" do
      rid = packet.rid
      meth = packet.method
      raw = packet.to_r
      packet.from_r(raw)
      packet.rid.should == rid
      packet.method.should == meth
    end
  end

  context "a response packet" do
    subject(:packet) {
      Rex::Post::Meterpreter::Packet.new(
        Rex::Post::Meterpreter::PACKET_TYPE_RESPONSE,
        "test_method"
      )
    }
    before(:each) do
      packet.add_tlv(Rex::Post::Meterpreter::TLV_TYPE_RESULT, "a-ok")
    end

    it "should return the correct result" do
      packet.result.should == "a-ok"
    end

    it "should evaluate result correctly" do
      packet.result?("a-ok").should == true
      packet.result?("5by5").should == false
    end

    it "should accept a new result" do
      packet.result = "test2"
      packet.result.should == "test2"
    end

    it "should be created when Packet.create_response is called" do
      resp = Rex::Post::Meterpreter::Packet.create_response
      resp.class.should == Rex::Post::Meterpreter::Packet
      resp.response?.should == true
    end

  end
end
