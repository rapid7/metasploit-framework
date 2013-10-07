require 'rex/exploitation/ropdb'

describe Rex::Exploitation::RopDb do
  context "Class methods" do

    context ".initialize" do
      it "should initialize with a path of the ROP database ready" do
        ropdb = Rex::Exploitation::RopDb.new
        ropdb.instance_variable_get(:@base_path).should =~ /data\/ropdb\/$/
      end
    end

    context ".has_rop?" do
      let(:ropdb) do
        Rex::Exploitation::RopDb.new
      end

      it "should find the msvcrt ROP database" do
        ropdb.has_rop?("msvcrt").should be_true
      end

      it "should find the java ROP database" do
        ropdb.has_rop?("java").should be_true
      end

      it "should find the hxds ROP database" do
        ropdb.has_rop?("hxds").should be_true
      end

      it "should find the flash ROP database" do
        ropdb.has_rop?("flash").should be_true
      end

      it "should return false when I supply an invalid database" do
        ropdb.has_rop?("sinn3r").should be_false
      end
    end

    context ".select_rop" do
      let(:ropdb) do
        Rex::Exploitation::RopDb.new
      end

      it "should return msvcrt gadgets" do
        gadgets = ropdb.select_rop('msvcrt')
        gadgets.length.should > 0
      end

      it "should return msvcrt gadgets for windows server 2003" do
        gadgets = ropdb.select_rop('msvcrt', {'target'=>'2003'})
        gadgets.length.should > 0
      end

      it "should return msvcrt gadgets with a new base" do
        gadgets1 = ropdb.select_rop('msvcrt')
        gadgets2 = ropdb.select_rop('msvcrt', {'base'=>0x10000000})

        gadgets2[0].should_not eq(gadgets1[0])
      end
    end

    context ".generate_rop_payload" do
      let(:ropdb) do
        Rex::Exploitation::RopDb.new
      end

      it "should generate my ROP payload" do
        ropdb.generate_rop_payload('msvcrt', 'AAAA').should =~ /AAAA$/
      end

      it "should generate my ROP payload with my stack pivot" do
        ropdb.generate_rop_payload('msvcrt', 'AAAA', {'pivot'=>'BBBB'}).should =~ /^BBBB/
      end
    end

    context ".get_safe_size" do
      let(:ropdb) do
        Rex::Exploitation::RopDb.new
      end

      it "should return 0xfffffed0 (value does not need to be modified to avoid null bytes)" do
        ropdb.send(:get_safe_size, 304).should eq(0xfffffed0)
      end

      it "should return 0xfffffeff (value is modified to avoid null bytes)" do
        ropdb.send(:get_safe_size, 256).should eq(0xfffffeff)
      end
    end

    context ".get_unsafe_size" do
      let(:ropdb) do
        Rex::Exploitation::RopDb.new
      end

      it "should return 0xfffffc00 (contains a null byte)" do
        ropdb.send(:get_unsafe_size, 1024).should eq(0xfffffc00)
      end
    end

  end
end