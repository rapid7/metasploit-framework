require 'rex/exploitation/js'

RSpec.describe Rex::Exploitation::Js::Utils do

  context "Class methods" do

    context ".base64" do
      it "should load the base64 javascript" do
        js = Rex::Exploitation::Js::Utils.base64
        expect(js).to match /encode : function/
      end
    end

  end

end
