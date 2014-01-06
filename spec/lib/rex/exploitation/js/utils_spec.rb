require 'rex/exploitation/js'

describe Rex::Exploitation::Js::Utils do

  context "Class methods" do

    context ".base64" do
      it "should load the base64 javascript" do
        js = Rex::Exploitation::Js::Utils.base64
        js.should =~ /encode : function/
      end
    end

  end

end