require 'rex/exploitation/ropdb'

RSpec.describe Rex::Exploitation::RopDb do

  subject(:ropdb) do
    described_class.new
  end

  context "Class methods" do

    context ".initialize" do
      it "should initialize with a path of the ROP database ready" do
        expect(ropdb.instance_variable_get(:@base_path)).to match /data\/ropdb\/$/
      end
    end

    context ".has_rop?" do
      it "should find the msvcrt ROP database" do
        expect(ropdb.has_rop?("msvcrt")).to be_truthy
      end

      it "should find the java ROP database" do
        expect(ropdb.has_rop?("java")).to be_truthy
      end

      it "should find the hxds ROP database" do
        expect(ropdb.has_rop?("hxds")).to be_truthy
      end

      it "should find the flash ROP database" do
        expect(ropdb.has_rop?("flash")).to be_truthy
      end

      it "should return false when I supply an invalid database" do
        expect(ropdb.has_rop?("sinn3r")).to be_falsey
      end
    end

    context ".select_rop" do
      it "should return msvcrt gadgets" do
        gadgets = ropdb.select_rop('msvcrt')
        expect(gadgets.length).to be > 0
      end

      it "should return msvcrt gadgets for windows server 2003" do
        gadgets = ropdb.select_rop('msvcrt', {'target'=>'2003'})
        expect(gadgets.length).to be > 0
      end

      it "should return msvcrt gadgets with a new base" do
        gadgets1 = ropdb.select_rop('msvcrt')
        gadgets2 = ropdb.select_rop('msvcrt', {'base'=>0x10000000})

        expect(gadgets2[0]).not_to eq(gadgets1[0])
      end
    end

    context ".generate_rop_payload" do
      it "should generate my ROP payload" do
        expect(ropdb.generate_rop_payload('msvcrt', 'AAAA')).to match /AAAA$/
      end

      it "should generate my ROP payload with my stack pivot" do
        expect(ropdb.generate_rop_payload('msvcrt', 'AAAA', {'pivot'=>'BBBB'})).to match /^BBBB/
      end
    end

    context ".get_safe_size" do
      it "should return 0xfffffed0 (value does not need to be modified to avoid null bytes)" do
        expect(ropdb.send(:get_safe_size, 304)).to eq(0xfffffed0)
      end

      it "should return 0xfffffeff (value is modified to avoid null bytes)" do
        expect(ropdb.send(:get_safe_size, 256)).to eq(0xfffffeff)
      end
    end

    context ".get_unsafe_size" do
      it "should return 0xfffffc00 (contains a null byte)" do
        expect(ropdb.send(:get_unsafe_size, 1024)).to eq(0xfffffc00)
      end
    end

  end
end
