require 'rex/exploitation/js'

describe Rex::Exploitation::Js::AddonsDetect do

  context "Class methods" do

    context ".initialize" do
      it "should load the Addons Detect javascript" do
        js = Rex::Exploitation::Js::AddonsDetect.new.to_s
        js.should =~ /window\.addons_detect/
      end
    end

  end

end