# -*- coding:binary -*-
require 'spec_helper'

require 'rex/mime'

describe Rex::MIME::Encoding do

  subject do
    mod = Class.new
    mod.extend described_class
    mod
  end

  describe "#force_crlf" do
    it "deletes \\r characters" do
      expect(subject.force_crlf("Test\r1\r")).to_not include("\\r")
    end

    it "substitutes \\n characters by \\r\\n sequences" do
      expect(subject.force_crlf("Test 2\n")).to end_with("\r\n")
    end

    it "preserves \r\n sequences" do
      expect(subject.force_crlf("\r\nTest 3\r\n")).to eq("\r\nTest 3\r\n")
    end

    it "first deletes \\r characters, then substitutes \\n characters" do
      expect(subject.force_crlf("\rTest 4\r\n\r\r\n")).to eq("Test 4\r\n\r\n")
    end
  end

end
