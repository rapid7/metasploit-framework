require 'rex/text'

describe Rex::Text do
  context "Class methods" do

    context ".to_octal" do
      it "should convert all chars 00 through ff" do
        described_class.to_octal("\x7f"*100).should eq("\\177"*100)

        all_chars = (0..0xff).map {|c| [c].pack("C") }.join
        all_octal = (0..0xff).map {|c| "\\%o"%(c) }.join
        described_class.to_octal(all_chars).should eq(all_octal)
      end
      it "should use the given prefix" do
        described_class.to_octal("\x7f"*100, "foo").should eq("foo177"*100)

        all_chars = (0..0xff).map {|c| [c].pack("C") }.join
        all_octal = (0..0xff).map {|c| "test%o"%(c) }.join
        described_class.to_octal(all_chars, "test").should eq(all_octal)
      end
    end

    context ".to_hex" do
      it "should convert all chars 00 through ff" do
        described_class.to_hex("\x7f"*100).should eq("\\x7f"*100)

        all_chars = (0..0xff).map {|c| [c].pack("C") }.join
        all_hex = (0..0xff).map {|c| "\\x%02x"%(c) }.join
        described_class.to_hex(all_chars).should eq(all_hex)
      end
      it "should use the given prefix" do
        described_class.to_hex("\x7f"*100, "foo").should eq("foo7f"*100)

        all_chars = (0..0xff).map {|c| [c].pack("C") }.join
        all_hex = (0..0xff).map {|c| "test%02x"%(c) }.join
        described_class.to_hex(all_chars, "test").should eq(all_hex)
      end
    end

    context ".to_hex_ascii" do
      it "should handle non-printables" do
        non_print = (0x7f..0xff).map {|c| [c].pack("C") }.join
        non_print_hex = (0x7f..0xff).map {|c| "\\x%02x"%(c) }.join
        described_class.to_hex_ascii(non_print).should eq(non_print_hex)

        described_class.to_hex_ascii("\x00").should eq("\\x00")
        described_class.to_hex_ascii("\x1f").should eq("\\x1f")
        described_class.to_hex_ascii("\x00"*100).should eq("\\x00"*100)
      end
      it "should not mess with printables" do
        described_class.to_hex_ascii("A").should eq("A")
        described_class.to_hex_ascii("A\x7f").should eq("A\\x7f")
      end
    end

    context ".gzip" do
      it "should return a properly formatted gzip file" do
        str = described_class.gzip("hi mom")
        str[0,4].should eq("\x1f\x8b\x08\x00") # Gzip magic
        # bytes 4 through 9 are a time stamp
        str[10..-1].should eq("\xcb\xc8\x54\xc8\xcd\xcf\x05\x00\x68\xa4\x1c\xf0\x06\x00\x00\x00")
      end
    end

    context ".ungzip" do
      it "should return an uncompressed string" do
        gzip  = "\x1f\x8b\x08\x00"
        gzip << "\x00" * 6
        gzip << "\xcb\xc8\x54\xc8\xcd\xcf\x05\x00\x68\xa4\x1c\xf0\x06\x00\x00\x00"
        described_class.ungzip(gzip).should eq("hi mom")
      end
    end

  end
end

