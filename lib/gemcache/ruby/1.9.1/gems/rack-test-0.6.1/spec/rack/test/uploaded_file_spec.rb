require "spec_helper"

describe Rack::Test::UploadedFile do
  def test_file_path
    File.dirname(__FILE__) + "/../../fixtures/foo.txt"
  end

  it "responds to things that Tempfile responds to" do
    uploaded_file = Rack::Test::UploadedFile.new(test_file_path)

    uploaded_file.should respond_to(:close)
    uploaded_file.should respond_to(:close!)
    uploaded_file.should respond_to(:delete)
    uploaded_file.should respond_to(:length)
    uploaded_file.should respond_to(:open)
    uploaded_file.should respond_to(:path)
    uploaded_file.should respond_to(:size)
    uploaded_file.should respond_to(:unlink)
    uploaded_file.should respond_to(:read)
  end

end
