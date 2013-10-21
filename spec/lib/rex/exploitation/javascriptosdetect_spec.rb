require 'rex/exploitation/javascriptosdetect'

describe Rex::Exploitation::JavascriptOSDetect do

  context "Class methods" do

    context ".initialize" do
      it "should load the OSDetect javascript" do
        js = Rex::Exploitation::JavascriptOSDetect.new.to_s
        js.should =~ /window\.os_detect/
      end
    end

  end

end