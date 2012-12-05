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

end