require 'rex/exploitation/js'

describe Rex::Exploitation::Js::OSDetect do

  context "Class methods" do

    context ".initialize" do
      it "should load the OSDetect javascript" do
        js = Rex::Exploitation::Js::OSDetect.new.to_s
        js.should =~ /window\.os_detect/
      end
    end

  end

end