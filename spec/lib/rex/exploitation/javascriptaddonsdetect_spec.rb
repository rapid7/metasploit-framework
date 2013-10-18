require 'rex/exploitation/javascriptaddonsdetect'

describe Rex::Exploitation::JavascriptAddonsDetect do

  subject(:ropdb) do
    described_class.new
  end

  context "Class methods" do

    context ".initialize" do
      it "should load the Addons Detect javascript" do
        js = Rex::Exploitation::JavascriptAddonsDetect.new.to_s
        js.should =~ /window\.addons_detect/
      end
    end

  end

end