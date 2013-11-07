require 'rex/exploitation/js'

describe Rex::Exploitation::Js::Network do

  context "Class methods" do

    context ".ajax_download" do
      it "should load the ajax_download javascript" do
        js = Rex::Exploitation::Js::Network.ajax_download
        js.should =~ /function ajax_download/
      end
    end

  end

end