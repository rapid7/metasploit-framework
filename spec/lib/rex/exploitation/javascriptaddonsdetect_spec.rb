require 'rex/exploitation/javascriptaddonsdetect'

describe Rex::Exploitation::JavascriptAddonsDetect do

  context "Class methods" do

    context ".initialize" do
      it "should load the Addons Detect javascript" do
        js = Rex::Exploitation::JavascriptAddonsDetect.new.to_s
        js.should =~ /window\.addons_detect/
      end
    end

  end

end