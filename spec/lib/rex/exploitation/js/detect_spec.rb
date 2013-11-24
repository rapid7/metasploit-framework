require 'rex/exploitation/js'

describe Rex::Exploitation::Js::Detect do

  context "Class methods" do

    context ".os" do
      it "should load the OS detection in Javascript" do
        js = Rex::Exploitation::Js::Detect.os.to_s
        js.should =~ /window\.os_detect/
      end
    end

    context ".ie_addons" do
      it "should load the IE Addons detection in Javascript" do
        js = Rex::Exploitation::Js::Detect.ie_addons.to_s
        js.should =~ /window\.ie_addons_detect/
      end
    end

    context ".misc_addons" do
      it "should load the misc Addons detection in Javascript" do
        js = Rex::Exploitation::Js::Detect.misc_addons.to_s
        js.should =~ /window\.misc_addons_detect/
      end
    end

  end

end