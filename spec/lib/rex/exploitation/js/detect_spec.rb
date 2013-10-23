require 'rex/exploitation/js'

describe Rex::Exploitation::Js::Detect do

  context "Class methods" do

    context ".os" do
      it "should load the OS Detect javascript" do
        js = Rex::Exploitation::Js::Detect.os.to_s
        js.should =~ /window\.os_detect/
      end
    end

    context ".addons" do
      it "should load the Addons Detect javascript" do
        js = Rex::Exploitation::Js::Detect.addons.to_s
        js.should =~ /window\.addons_detect/
      end
    end

  end

end