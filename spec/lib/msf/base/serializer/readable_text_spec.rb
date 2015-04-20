require 'spec_helper'
require 'msf/base/serializer/readable_text'
# require 'rex/post/meterpreter/extensions/stdapi/net/interface'
# require 'rex/post/meterpreter/extensions/stdapi/net/route'

describe Msf::Serializer::ReadableText do

  let (:subject) {
    described_class
  }
  it "should format text bold" do
     res = subject.format_text("test", :bold)
    expect(res).to eq '%bldtest%clr'

  end
  it "should format text underlie" do
    res = subject.format_text("test", :underline)
    expect(res).to eq '%undtest%clr'

  end


end

