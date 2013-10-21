require 'rex/exploitation/javascriptnetwork'

describe Rex::Exploitation::JavascriptNetwork do

  context "Class methods" do

    context ".ajax_download" do
      it "should load the ajax_download javascript" do
        js = Rex::Exploitation::JavascriptNetwork.ajax_download
        js.should =~ /function ajax_download/
      end
    end

  end

end