require 'rex/exploitation/js'

RSpec.describe Rex::Exploitation::Js::Network do

  context "Class methods" do

    context ".ajax_download" do
      it "should load the ajax_download javascript" do
        js = Rex::Exploitation::Js::Network.ajax_download
        expect(js).to =~ /function ajax_download/
      end
    end

    context ".ajax_post" do
      it "should load the postInfo javascript" do
        js = Rex::Exploitation::Js::Network.ajax_post
        expect(js).to =~ /function postInfo/
      end
    end

  end

end
