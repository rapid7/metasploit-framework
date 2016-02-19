require 'rex/exploitation/js'

RSpec.describe Rex::Exploitation::Js::Detect do

  context "Class methods" do

    context ".os" do
      it "should load the OS detection in Javascript" do
        js = Rex::Exploitation::Js::Detect.os.to_s
        expect(js).to match /os_detect/
      end
    end

    context ".ie_addons" do
      it "should load the IE Addons detection in Javascript" do
        js = Rex::Exploitation::Js::Detect.ie_addons.to_s
        expect(js).to match /ie_addons_detect/
      end
    end

    context ".misc_addons" do
      it "should load the misc Addons detection in Javascript" do
        js = Rex::Exploitation::Js::Detect.misc_addons.to_s
        expect(js).to match /misc_addons_detect/
      end
    end

  end

end
