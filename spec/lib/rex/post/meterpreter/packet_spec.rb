# -*- coding:binary -*-
require 'rex/post/meterpreter/packet'

RSpec.describe Rex::Post::Meterpreter::Tlv do
  subject(:tlv) {
    Rex::Post::Meterpreter::Tlv.new(
      Rex::Post::Meterpreter::TLV_TYPE_STRING,
      "test"
    )
  }

  it "should respond to type" do
    expect(tlv).to respond_to :type
  end

  it "should respond to value" do
    expect(tlv).to respond_to :value
  end

  it "should respond to compress" do
    expect(tlv).to respond_to :compress
  end

  it "should respond to inspect" do
    expect(tlv).to respond_to :inspect
  end

  it "should respond to meta_type?" do
    expect(tlv).to respond_to :meta_type?
  end

  it "should respond to type?" do
    expect(tlv).to respond_to :type?
  end

  it "should respond to value?" do
    expect(tlv).to respond_to :value?
  end

  it "should respond to to_r" do
    expect(tlv).to respond_to :to_r
  end

  it "should respond to from_r" do
    expect(tlv).to respond_to :from_r
  end

  context "A String TLV" do
    it "should return the correct TLV type" do
      expect(tlv.type).to eq Rex::Post::Meterpreter::TLV_TYPE_STRING
    end

    it "should return the correct value" do
      expect(tlv.value).to eq "test"
    end

    context "#type?" do
      it "should return true for STRING" do
        expect(tlv.type?(Rex::Post::Meterpreter::TLV_TYPE_STRING)).to eq true
      end

      it "should return false for UINT" do
        expect(tlv.type?(Rex::Post::Meterpreter::TLV_TYPE_UINT)).to eq false
      end
    end

    context "#value?" do
      it "should return true for the correct value" do
        expect(tlv.value?("test")).to eq true
      end

      it "should return false for an incorrect value" do
        expect(tlv.value?("fake")).to eq false
      end
    end

    context "#inspect" do
      it "should return a string representation of the TLV" do
        tlv_to_s = "#<Rex::Post::Meterpreter::Tlv type=STRING          meta=STRING     value=\"test\">"
        expect(tlv.inspect).to eq tlv_to_s
      end
    end

    context "Any non group TLV_TYPE" do
      subject(:tlv_types){
        excludedTypes = ["TLV_TYPE_ANY", "TLV_TYPE_EXCEPTION", "TLV_TYPE_CHANNEL_DATA_GROUP", "TLV_TYPE_TRANS_GROUP"]
        typeList = []
        Rex::Post::Meterpreter.constants.each do |type|
          typeList << type.to_s if type.to_s.include?("TLV_TYPE") && !excludedTypes.include?(type.to_s)
        end
        typeList
      }

      it "will not raise error on inspect" do
        tlv_types.each do |type|
          inspectable = Rex::Post::Meterpreter::Tlv.new(
              Rex::Post::Meterpreter.const_get(type),
              "test"
          )
          expect(inspectable.inspect).to be_a_kind_of String
        end
      end
    end

    context "#to_r" do
      it "should return the raw bytes of the TLV to send over the wire" do
        tlv_bytes = "\x00\x00\x00\r\x00\x01\x00\ntest\x00"
        expect(tlv.to_r).to eq tlv_bytes
      end
    end

    context "#from_r" do
      it "should adjust the tlv attributes from the given raw bytes" do
        tlv.from_r("\x00\x00\x00\r\x00\x01\x00\ntes2\x00")
        expect(tlv.value).to eq "tes2"
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
      expect(tlv.meta_type?(Rex::Post::Meterpreter::TLV_META_TYPE_STRING)).to eq true
    end

    it "should show the correct type and meta type in inspect" do
      tlv_to_s = "#<Rex::Post::Meterpreter::Tlv type=METHOD          meta=STRING     value=\"test\">"
      expect(tlv.inspect).to eq tlv_to_s
    end
  end

  context "A String TLV with a number value" do
    subject(:tlv) {
      Rex::Post::Meterpreter::Tlv.new(Rex::Post::Meterpreter::TLV_TYPE_STRING,5)
    }
    it "should return the string version of the number" do
      expect(tlv.value).to eq "5"
    end
  end

end

RSpec.describe Rex::Post::Meterpreter::GroupTlv do
  subject(:group_tlv) {
    Rex::Post::Meterpreter::GroupTlv.new(
      Rex::Post::Meterpreter::TLV_TYPE_CHANNEL_DATA_GROUP
    )
  }

  it "should respond to tlvs" do
    expect(group_tlv).to respond_to :tlvs
  end

  it "should respond to each" do
    expect(group_tlv).to respond_to :each
  end

  it "should respond to each_tlv" do
    expect(group_tlv).to respond_to :each_tlv
  end

  it "should respond to each_with_index" do
    expect(group_tlv).to respond_to :each_with_index
  end

  it "should respond to each_tlv_with_index" do
    expect(group_tlv).to respond_to :each_tlv_with_index
  end

  it "should respond to get_tlvs" do
    expect(group_tlv).to respond_to :get_tlvs
  end

  it "should respond to add_tlv" do
    expect(group_tlv).to respond_to :add_tlv
  end

  it "should respond to add_tlvs" do
    expect(group_tlv).to respond_to :add_tlvs
  end

  it "should respond to get_tlv" do
    expect(group_tlv).to respond_to :get_tlv
  end

  it "should respond to get_tlv_value" do
    expect(group_tlv).to respond_to :get_tlv_value
  end

  it "should respond to get_tlv_values" do
    expect(group_tlv).to respond_to :get_tlv_values
  end

  it "should respond to has_tlv?" do
    expect(group_tlv).to respond_to :has_tlv?
  end

  it "should respond to reset" do
    expect(group_tlv).to respond_to :reset
  end

  it "should respond to to_r" do
    expect(group_tlv).to respond_to :to_r
  end

  it "should respond to from_r" do
    expect(group_tlv).to respond_to :from_r
  end

  it "should return an empty array for tlvs by default" do
    expect(group_tlv.tlvs).to eq []
  end

  context "#add_tlv" do
    it "should add to the tlvs array when given basic tlv paramaters" do
      group_tlv.add_tlv(Rex::Post::Meterpreter::TLV_TYPE_STRING,"test")
      expect(group_tlv.tlvs.first.type).to eq Rex::Post::Meterpreter::TLV_TYPE_STRING
      expect(group_tlv.tlvs.first.value).to eq "test"
    end

    it  "should replace any existing TLV of the same type when the replace flag is set to true" do
      group_tlv.add_tlv(Rex::Post::Meterpreter::TLV_TYPE_STRING,"test")
      group_tlv.add_tlv(Rex::Post::Meterpreter::TLV_TYPE_STRING,"test2", true)
      expect(group_tlv.tlvs.count).to eq 1
      expect(group_tlv.tlvs.first.value).to eq "test2"
    end

    it "should add both if replace is set to false" do
      group_tlv.add_tlv(Rex::Post::Meterpreter::TLV_TYPE_STRING,"test")
      group_tlv.add_tlv(Rex::Post::Meterpreter::TLV_TYPE_STRING,"test2", false)
      expect(group_tlv.tlvs.first.value).to eq "test"
      expect(group_tlv.tlvs.last.value).to eq "test2"
    end
  end

  context "#add_tlvs" do
    it "should be able to add an array of type-value hashes" do
      tlv_array = [
        {'type' => Rex::Post::Meterpreter::TLV_TYPE_STRING, 'value' => "test"},
        {'type' => Rex::Post::Meterpreter::TLV_TYPE_STRING, 'value' => "test2"}
      ]
      group_tlv.add_tlvs(tlv_array)
      expect(group_tlv.tlvs.count).to eq 2
      expect(group_tlv.tlvs.first.value).to eq "test"
      expect(group_tlv.tlvs.last.value).to eq "test2"
    end

    it "should raise an error when given something other than nil or an array" do
      skip "RM #7598"
      expect(group_tlv.add_tlvs("bad value")).to raise_error
    end

    it "should raise an error when given an array of objects other than hashes" do
      skip "RM #7598"
      expect(group_tlv.add_tlvs([1,2,3])).to raise_error
    end

    it "should raise an error when any of the hashes are missing a key" do
      skip "RM #7598"
      tlv_array = [
        {:type => Rex::Post::Meterpreter::TLV_TYPE_STRING, :value => "test"},
        {:type => Rex::Post::Meterpreter::TLV_TYPE_STRING}
      ]
      expect(group_tlv.add_tlvs(tlv_array)).to raise_error
    end
  end

  context "with TLVs added" do
    before(:example) do
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
      expect(group_tlv.tlvs).to eq []
    end

    it "should convert to raw bytes when to_r is called" do
      expect(group_tlv.to_r).to eq @raw_group
    end


    context "#from_r" do
      it "should build the TLV group when given the propper raw bytes" do
        group_tlv.reset
        group_tlv.from_r( @raw_group)
        expect(group_tlv.tlvs[0].inspect).to eq "#<Rex::Post::Meterpreter::Tlv type=STRING          meta=STRING     value=\"test\">"
        expect(group_tlv.tlvs[1].inspect).to eq "#<Rex::Post::Meterpreter::Tlv type=STRING          meta=STRING     value=\"test2\">"
        expect(group_tlv.tlvs[2].inspect).to eq "#<Rex::Post::Meterpreter::Tlv type=UINT            meta=INT        value=5>"
      end
    end


    context "#get_tlvs" do
      it "should return all TLVs of the supplied type" do
        tlvs = group_tlv.get_tlvs(Rex::Post::Meterpreter::TLV_TYPE_STRING)
        expect(tlvs.count).to eq 2
        expect(tlvs.first.value).to eq "test"
        expect(tlvs.last.value).to eq "test2"
      end

      it "should return all TLVs when supplied the ANY TLV type" do
        tlvs = group_tlv.get_tlvs(Rex::Post::Meterpreter::TLV_TYPE_ANY)
        expect(tlvs.count).to eq group_tlv.tlvs.count
      end

      it "should return an empty array for a TLV type that isn't present" do
        expect(group_tlv.get_tlvs(Rex::Post::Meterpreter::TLV_TYPE_BOOL)).to eq []
      end

      it "should return an empty array for a nonexistant TLV type" do
        expect(group_tlv.get_tlvs(55555555)).to eq []
      end
    end

    context "#get_tlv" do
      it "should return the first TLV of the specified type by default" do
        expect(group_tlv.get_tlv(Rex::Post::Meterpreter::TLV_TYPE_STRING)).to eq group_tlv.tlvs.first
        expect(group_tlv.get_tlv(Rex::Post::Meterpreter::TLV_TYPE_UINT)).to eq group_tlv.tlvs.last
      end

      it "should return the correct TLV of the specified type for the given index" do
        expect(group_tlv.get_tlv(Rex::Post::Meterpreter::TLV_TYPE_STRING,1)).to eq group_tlv.tlvs[1]
      end

      it "should return nil if given an out of bounds index" do
        expect(group_tlv.get_tlv(Rex::Post::Meterpreter::TLV_TYPE_STRING,5)).to eq nil
      end

      it "should return nil if given a non-present TLV type" do
        expect(group_tlv.get_tlv(Rex::Post::Meterpreter::TLV_TYPE_BOOL)).to eq nil
      end
    end

    context "#get_tlv_value" do
      it "should return the value of the first TLV with the given type" do
        expect(group_tlv.get_tlv_value(Rex::Post::Meterpreter::TLV_TYPE_STRING)).to eq group_tlv.tlvs.first.value
      end

      it "should return the correct TLV value of the specified type for the given index" do
        expect(group_tlv.get_tlv_value(Rex::Post::Meterpreter::TLV_TYPE_STRING,1)).to eq group_tlv.tlvs[1].value
      end

      it "should return nil if given an out of bounds index" do
        expect(group_tlv.get_tlv_value(Rex::Post::Meterpreter::TLV_TYPE_STRING,5)).to eq nil
      end

      it "should return nil if given a non-present TLV type" do
        expect(group_tlv.get_tlv_value(Rex::Post::Meterpreter::TLV_TYPE_BOOL)).to eq nil
      end
    end

    context "#get_tlv_values" do
      it "should return an array of values for the designated TLV types" do
        expect(group_tlv.get_tlv_values(Rex::Post::Meterpreter::TLV_TYPE_STRING)).to eq ["test", "test2"]
      end

      it "should return an empty array for a non-present TLV type" do
        expect(group_tlv.get_tlv_values(Rex::Post::Meterpreter::TLV_TYPE_BOOL)).to eq []
      end
    end

    context "#has_tlv?" do
      it "should return true if the TLV Type is present" do
        expect(group_tlv.has_tlv?(Rex::Post::Meterpreter::TLV_TYPE_STRING)).to eq true
      end

      it "should return false if the TLV type is not present" do
        expect(group_tlv.has_tlv?(Rex::Post::Meterpreter::TLV_TYPE_BOOL)).to eq false
      end
    end
  end
end

RSpec.describe Rex::Post::Meterpreter::Packet do
  context "Request Packet" do
    subject(:packet) {
      Rex::Post::Meterpreter::Packet.new(
        Rex::Post::Meterpreter::PACKET_TYPE_REQUEST,
        "test_method"
      )
    }

    it "should respond to created_at" do
      expect(packet).to respond_to :created_at
    end

    it "should respond to response?" do
      expect(packet).to respond_to :response?
    end

    it "should respond to method?" do
      expect(packet).to respond_to :method?
    end

    it "should respond to method" do
      expect(packet).to respond_to :method
    end

    it "should respond to result?" do
      expect(packet).to respond_to :result?
    end

    it "should respond to result=" do
      expect(packet).to respond_to :result=
    end

    it "should respond to result" do
      expect(packet).to respond_to :result
    end

    it "should respond to rid" do
      expect(packet).to respond_to :rid
    end

    it "should return false for response?" do
      expect(packet.response?).to eq false
    end

    it "should evaluate the method correctly" do
      expect(packet.method?("test_method")).to eq true
      expect(packet.method?("blah")).to eq false
    end

    it "should accept new methods" do
      packet.method= "test_method2"
      expect(packet.method?("test_method2")).to eq true
    end

    it "should return the correct method" do
      expect(packet.method).to eq "test_method"
    end

    it "should not have a result" do
      expect(packet.result).to eq nil
    end

    it "should return a valid request id" do
      expect(packet.rid).to match /\A\d{32}\Z/
    end

    it "should be created when Packet.create_request is called" do
      req = Rex::Post::Meterpreter::Packet.create_request("test_method")
      expect(req.class).to eq Rex::Post::Meterpreter::Packet
      expect(req.response?).to eq false
      expect(req.method?("test_method")).to eq true
    end

    it "should return the correct raw byte form of the packet" do
      rid = packet.rid
      meth = packet.method
      raw = packet.to_r
      packet.add_raw(raw)
      packet.from_r
      expect(packet.rid).to eq rid
      expect(packet.method).to eq meth
    end
  end

  context "a response packet" do
    subject(:packet) {
      Rex::Post::Meterpreter::Packet.new(
        Rex::Post::Meterpreter::PACKET_TYPE_RESPONSE,
        "test_method"
      )
    }
    before(:example) do
      packet.add_tlv(Rex::Post::Meterpreter::TLV_TYPE_RESULT, "a-ok")
    end

    it "should return the correct result" do
      expect(packet.result).to eq "a-ok"
    end

    it "should evaluate result correctly" do
      expect(packet.result?("a-ok")).to eq true
      expect(packet.result?("5by5")).to eq false
    end

    it "should accept a new result" do
      packet.result = "test2"
      expect(packet.result).to eq "test2"
    end

    it "should be created when Packet.create_response is called" do
      resp = Rex::Post::Meterpreter::Packet.create_response
      expect(resp.class).to eq Rex::Post::Meterpreter::Packet
      expect(resp.response?).to eq true
    end

  end
end
