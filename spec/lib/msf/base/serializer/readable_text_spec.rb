require 'spec_helper'
require 'msf/base/serializer/readable_text'

describe Msf::Serializer::ReadableText do

  let (:subject) {
    described_class
  }
  it "should format text bold" do
     res = subject.format_text("test", :bold)
    expect(res).to eq '%bldtest%clr'

  end
  it "should format text underline" do
    res = subject.format_text("test", :underline)
    expect(res).to eq '%undtest%clr'

  end

  it "should parse titles" do
    res = subject.md_parse("#test")
    expect(res).to eq '%bldtest%clr'
  end
  it "should parse titles ignoring title depth" do
    res = subject.md_parse("###test")
    expect(res).to eq '%bldtest%clr'
  end

  it "should parse titles even with arbitrary spaces" do
    res = subject.md_parse("#               test")
    expect(res).to eq '%bldtest%clr'
  end
  it "should format text underline and not ignore spaces" do
    res = subject.format_text("    test", :underline)
    expect(res).to eq '%und    test%clr'

  end

  it "should parse text as bold when surrounded by asterisks" do
    res = subject.md_parse("*test*")
    expect(res).to eq '%bldtest%clr'
  end

  it "should parse multiple bold segments in a single line" do
    res = subject.md_parse("*one* and *two*")
    expect(res).to eq "%bldone%clr and %bldtwo%clr"
  end

end

