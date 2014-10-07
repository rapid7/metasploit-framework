shared_examples_for "Rex::Encoder::NDR.wstring_prebuild" do
  context "when 2-byte aligned string length" do
    let(:string) { "A\x00B\x00C\x00" }

    it "encodes the argument as null-terminated unicode string" do
      is_expected.to include("A\x00B\x00C\x00")
    end

    it "starts encoding string metadata" do
      expect(subject.unpack("VVV")[0]).to eq(string.length / 2)
      expect(subject.unpack("VVV")[1]).to eq(0)
      expect(subject.unpack("VVV")[2]).to eq(string.length / 2)
    end

    it "ends with padding to make result length 32-bits aligned" do
      is_expected.to end_with("\x00" * 2)
      expect(subject.length).to eq(20)
    end
  end

  context "when 2-byte unaligned string length" do
    let(:string) { "A\x00B\x00C" }

    it "encodes the argument as null-terminated unicode string" do
      is_expected.to include("A\x00B\x00C\x00")
    end

    it "starts encoding string metadata" do
      expect(subject.unpack("VVV")[0]).to eq((string.length + 1) / 2)
      expect(subject.unpack("VVV")[1]).to eq(0)
      expect(subject.unpack("VVV")[2]).to eq((string.length + 1) / 2)
    end

    it "ends with padding to make result length 32-bits aligned" do
      is_expected.to end_with("\x00" * 2)
      expect(subject.length).to eq(20)
    end
  end
end