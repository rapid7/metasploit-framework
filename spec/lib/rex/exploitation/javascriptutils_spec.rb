require 'rex/exploitation/javascriptutils'

describe Rex::Exploitation::JavascriptUtils do

  subject(:ropdb) do
    described_class.new
  end

  context "Class methods" do

    context ".base64" do
      it "should load the base64 javascript" do
        js = Rex::Exploitation::JavascriptUtils.base64
        js.should =~ /encode : function/
      end
    end

  end

end