# encoding: UTF-8

require "spec_helper"

describe Rack::Test::Session do

  def test_file_path
    File.dirname(__FILE__) + "/../../fixtures/foo.txt"
  end

  def second_test_file_path
    File.dirname(__FILE__) + "/../../fixtures/bar.txt"
  end

  def uploaded_file
    Rack::Test::UploadedFile.new(test_file_path)
  end

  def second_uploaded_file
    Rack::Test::UploadedFile.new(second_test_file_path)
  end

  context "uploading a file" do
    it "sends the multipart/form-data content type" do
      post "/", "photo" => uploaded_file
      last_request.env["CONTENT_TYPE"].should include("multipart/form-data;")
    end

    it "sends regular params" do
      post "/", "photo" => uploaded_file, "foo" => "bar"
      last_request.POST["foo"].should == "bar"
    end

    it "sends nested params" do
      post "/", "photo" => uploaded_file, "foo" => {"bar" => "baz"}
      last_request.POST["foo"]["bar"].should == "baz"
    end

    it "sends multiple nested params" do
      post "/", "photo" => uploaded_file, "foo" => {"bar" => {"baz" => "bop"}}
      last_request.POST["foo"]["bar"]["baz"].should == "bop"
    end

    it "sends params with arrays" do
      post "/", "photo" => uploaded_file, "foo" => ["1", "2"]
      last_request.POST["foo"].should == ["1", "2"]
    end

    it "sends params with encoding sensitive values" do
      post "/", "photo" => uploaded_file, "foo" => "bar? baz"
      last_request.POST["foo"].should == "bar? baz"
    end

    it "sends params encoded as ISO-8859-1" do
      post "/", "photo" => uploaded_file, "foo" => "bar", "utf8" => "☃"
      last_request.POST["foo"].should == "bar"

      if Rack::Test.encoding_aware_strings?
        last_request.POST["utf8"].should == "☃"
      else
        last_request.POST["utf8"].should == "\xE2\x98\x83"
      end
    end

    it "sends params with parens in names" do
      post "/", "photo" => uploaded_file, "foo(1i)" => "bar"
      last_request.POST["foo(1i)"].should == "bar"
    end

    it "sends params with encoding sensitive names" do
      post "/", "photo" => uploaded_file, "foo bar" => "baz"
      last_request.POST["foo bar"].should == "baz"
    end

    it "sends files with the filename" do
      post "/", "photo" => uploaded_file
      last_request.POST["photo"][:filename].should == "foo.txt"
    end

    it "sends files with the text/plain MIME type by default" do
      post "/", "photo" => uploaded_file
      last_request.POST["photo"][:type].should == "text/plain"
    end

    it "sends files with the right name" do
      post "/", "photo" => uploaded_file
      last_request.POST["photo"][:name].should == "photo"
    end

    it "allows overriding the content type" do
      post "/", "photo" => Rack::Test::UploadedFile.new(test_file_path, "image/jpeg")
      last_request.POST["photo"][:type].should == "image/jpeg"
    end

    it "sends files with a Content-Length in the header" do
      post "/", "photo" => uploaded_file
      last_request.POST["photo"][:head].should include("Content-Length: 4")
    end

    it "sends files as Tempfiles" do
      post "/", "photo" => uploaded_file
      last_request.POST["photo"][:tempfile].should be_a(::Tempfile)
    end
  end


  context "uploading two files" do
    it "sends the multipart/form-data content type" do
      post "/", "photos" => [uploaded_file, second_uploaded_file]
      last_request.env["CONTENT_TYPE"].should include("multipart/form-data;")
    end

    it "sends files with the filename" do
      post "/", "photos" => [uploaded_file, second_uploaded_file]
      last_request.POST["photos"].collect{|photo| photo[:filename]}.should == ["foo.txt", "bar.txt"]
    end

    it "sends files with the text/plain MIME type by default" do
      post "/", "photos" => [uploaded_file, second_uploaded_file]
      last_request.POST["photos"].collect{|photo| photo[:type]}.should == ["text/plain", "text/plain"]
    end

    it "sends files with the right names" do
      post "/", "photos" => [uploaded_file, second_uploaded_file]
      last_request.POST["photos"].all?{|photo| photo[:name].should == "photos[]" }
    end

    it "allows mixed content types" do
      image_file = Rack::Test::UploadedFile.new(test_file_path, "image/jpeg")

      post "/", "photos" => [uploaded_file, image_file]
      last_request.POST["photos"].collect{|photo| photo[:type]}.should == ["text/plain", "image/jpeg"]
    end

    it "sends files with a Content-Length in the header" do
      post "/", "photos" => [uploaded_file, second_uploaded_file]
      last_request.POST["photos"].all?{|photo| photo[:head].should include("Content-Length: 4") }
    end

    it "sends both files as Tempfiles" do
      post "/", "photos" => [uploaded_file, second_uploaded_file]
      last_request.POST["photos"].all?{|photo| photo[:tempfile].should be_a(::Tempfile) }
    end
  end
end
