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

    context ".rand_surname" do
      it "should return a random surname" do
        described_class::Surnames.should include(described_class.rand_surname)
      end
    end

    context ".rand_name" do
      it "should return a random name" do
        names = described_class::Names_Female + described_class::Names_Male
        names.should include(described_class.rand_name)
      end
    end

    context ".rand_name_female" do
      it "should return a random female name" do
        described_class::Names_Female.should include(described_class.rand_name_female)
      end
    end

    context ".rand_name_male" do
      it "should return a random male name" do
        described_class::Names_Male.should include(described_class.rand_name_male)
      end
    end

    context ".rand_mail_address" do
      it "should return a random mail address" do
        names = described_class::Names_Female + described_class::Names_Male
        surnames = described_class::Surnames
        tlds = described_class::TLDs

        # XXX: This is kinda dirty
        mail_address = described_class.rand_mail_address.split("@").map { |x| x.split(".") }
        name, surname = mail_address.first.first, mail_address.first.last
        domain, tld = "example", mail_address.last.last # Poor man's stubbing to preserve TLD

        names.should include(name)
        surnames.should include(surname)
        domain.should eq("example")
        tlds.should include(tld)
      end
    end

    context ".randomize_space" do
      let (:sample_text) { "The quick brown sploit jumped over the lazy A/V" }
      let (:spaced_text) { described_class.randomize_space(sample_text) }
      it "should return a string with at least one new space characater" do
        spaced_text.should match /[\x09\x0d\x0a]/
      end

      it "should not otherwise be mangled" do
        normalized_text = spaced_text.gsub(/[\x20\x09\x0d\x0a]+/m, " ")
        normalized_text.should eq(sample_text)
      end
    end

  end
end

