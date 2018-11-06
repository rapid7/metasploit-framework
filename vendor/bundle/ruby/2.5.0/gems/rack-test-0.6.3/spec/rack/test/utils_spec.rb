require "spec_helper"

describe Rack::Test::Utils do
  include Rack::Test::Utils

  describe "build_nested_query" do
    it "converts empty strings to =" do
      build_nested_query("").should == "="
    end

    it "converts nil to an empty string" do
      build_nested_query(nil).should == ""
    end

    it "converts hashes with nil values" do
      build_nested_query(:a => nil).should == "a"
    end

    it "converts hashes" do
      build_nested_query(:a => 1).should == "a=1"
    end

    it "converts hashes with multiple keys" do
      hash = { :a => 1, :b => 2 }
      ["a=1&b=2", "b=2&a=1"].should include(build_nested_query(hash))
    end

    it "converts arrays with one element" do
      build_nested_query(:a => [1]).should == "a[]=1"
    end

    it "converts arrays with multiple elements" do
      build_nested_query(:a => [1, 2]).should == "a[]=1&a[]=2"
    end

    it "converts arrays with brackets '[]' in the name" do
      build_nested_query("a[]" => [1, 2]).should == "a%5B%5D=1&a%5B%5D=2"
    end

    it "converts nested hashes" do
      build_nested_query(:a => { :b => 1 }).should == "a[b]=1"
    end

    it "converts arrays nested in a hash" do
      build_nested_query(:a => { :b => [1, 2] }).should == "a[b][]=1&a[b][]=2"
    end

    it "converts arrays of hashes" do
      build_nested_query(:a => [{ :b => 2}, { :c => 3}]).should == "a[][b]=2&a[][c]=3"
    end
  end

  describe "build_multipart" do
    it "builds multipart bodies" do
      files = Rack::Test::UploadedFile.new(multipart_file("foo.txt"))
      data  = build_multipart("submit-name" => "Larry", "files" => files)

      options = {
        "CONTENT_TYPE" => "multipart/form-data; boundary=#{Rack::Test::MULTIPART_BOUNDARY}",
        "CONTENT_LENGTH" => data.length.to_s,
        :input => StringIO.new(data)
      }
      env = Rack::MockRequest.env_for("/", options)
      params = Rack::Utils::Multipart.parse_multipart(env)
      check params["submit-name"].should == "Larry"
      check params["files"][:filename].should == "foo.txt"
      params["files"][:tempfile].read.should == "bar\n"
    end

   it "builds multipart bodies from array of files" do
      files = [Rack::Test::UploadedFile.new(multipart_file("foo.txt")), Rack::Test::UploadedFile.new(multipart_file("bar.txt"))]
      data  = build_multipart("submit-name" => "Larry", "files" => files)

      options = {
        "CONTENT_TYPE" => "multipart/form-data; boundary=#{Rack::Test::MULTIPART_BOUNDARY}",
        "CONTENT_LENGTH" => data.length.to_s,
        :input => StringIO.new(data)
      }
      env = Rack::MockRequest.env_for("/", options)
      params = Rack::Utils::Multipart.parse_multipart(env)
      check params["submit-name"].should == "Larry"

      check params["files"][0][:filename].should == "foo.txt"
      params["files"][0][:tempfile].read.should == "bar\n"

      check params["files"][1][:filename].should == "bar.txt"
      params["files"][1][:tempfile].read.should == "baz\n"
    end

    it "builds nested multipart bodies" do
      files = Rack::Test::UploadedFile.new(multipart_file("foo.txt"))
      data  = build_multipart("people" => [{"submit-name" => "Larry", "files" => files}], "foo" => ['1', '2'])

      options = {
        "CONTENT_TYPE" => "multipart/form-data; boundary=#{Rack::Test::MULTIPART_BOUNDARY}",
        "CONTENT_LENGTH" => data.length.to_s,
        :input => StringIO.new(data)
      }
      env = Rack::MockRequest.env_for("/", options)
      params = Rack::Utils::Multipart.parse_multipart(env)
      check params["people"][0]["submit-name"].should == "Larry"
      check params["people"][0]["files"][:filename].should == "foo.txt"
      params["people"][0]["files"][:tempfile].read.should == "bar\n"
      check params["foo"].should == ["1", "2"]
    end

    it "builds nested multipart bodies with an array of hashes" do
      files = Rack::Test::UploadedFile.new(multipart_file("foo.txt"))
      data  = build_multipart("files" => files, "foo" => [{"id" => "1", "name" => 'Dave'}, {"id" => "2", "name" => 'Steve'}])

      options = {
        "CONTENT_TYPE" => "multipart/form-data; boundary=#{Rack::Test::MULTIPART_BOUNDARY}",
        "CONTENT_LENGTH" => data.length.to_s,
        :input => StringIO.new(data)
      }
      env = Rack::MockRequest.env_for("/", options)
      params = Rack::Utils::Multipart.parse_multipart(env)
      check params["files"][:filename].should == "foo.txt"
      params["files"][:tempfile].read.should == "bar\n"
      check params["foo"].should == [{"id" => "1", "name" => "Dave"}, {"id" => "2", "name" => "Steve"}]
    end

    it "builds nested multipart bodies with arbitrarily nested array of hashes" do
      files = Rack::Test::UploadedFile.new(multipart_file("foo.txt"))
      data  = build_multipart("files" => files, "foo" => {"bar" => [{"id" => "1", "name" => 'Dave'},
                                                                    {"id" => "2", "name" => 'Steve', "qux" => [{"id" => '3', "name" => 'mike'},
                                                                                                               {"id" => '4', "name" => 'Joan'}]}]})

      options = {
        "CONTENT_TYPE" => "multipart/form-data; boundary=#{Rack::Test::MULTIPART_BOUNDARY}",
        "CONTENT_LENGTH" => data.length.to_s,
        :input => StringIO.new(data)
      }
      env = Rack::MockRequest.env_for("/", options)
      params = Rack::Utils::Multipart.parse_multipart(env)
      check params["files"][:filename].should == "foo.txt"
      params["files"][:tempfile].read.should == "bar\n"
      check params["foo"].should == {"bar" => [{"id" => "1", "name" => "Dave"},
                                               {"id" => "2", "name" => "Steve", "qux" => [{"id" => '3', "name" => 'mike'},
                                                                                          {"id" => '4', "name" => 'Joan'}]}]}
    end

    it 'does not break with params that look nested, but are not' do
      files = Rack::Test::UploadedFile.new(multipart_file("foo.txt"))
      data  = build_multipart("foo[]" => "1", "bar[]" => {"qux" => "2"}, "files[]" => files)

      options = {
        "CONTENT_TYPE" => "multipart/form-data; boundary=#{Rack::Test::MULTIPART_BOUNDARY}",
        "CONTENT_LENGTH" => data.length.to_s,
        :input => StringIO.new(data)
      }
      env = Rack::MockRequest.env_for("/", options)
      params = Rack::Utils::Multipart.parse_multipart(env)
      check params["files"][0][:filename].should == "foo.txt"
      params["files"][0][:tempfile].read.should == "bar\n"
      check params["foo"][0].should == "1"
      check params["bar"][0].should == {"qux" => "2"}
    end

    it 'allows for nested files' do
      files = Rack::Test::UploadedFile.new(multipart_file("foo.txt"))
      data  = build_multipart("foo" => [{"id" => "1", "data" => files},
                                        {"id" => "2", "data" => ["3", "4"]}])

      options = {
        "CONTENT_TYPE" => "multipart/form-data; boundary=#{Rack::Test::MULTIPART_BOUNDARY}",
        "CONTENT_LENGTH" => data.length.to_s,
        :input => StringIO.new(data)
      }
      env = Rack::MockRequest.env_for("/", options)
      params = Rack::Utils::Multipart.parse_multipart(env)
      check params["foo"][0]["id"].should == "1"
      check params["foo"][0]["data"][:filename].should == "foo.txt"
      params["foo"][0]["data"][:tempfile].read.should == "bar\n"
      check params["foo"][1].should == {"id" => "2", "data" => ["3", "4"]}
    end

    it "returns nil if no UploadedFiles were used" do
      data = build_multipart("people" => [{"submit-name" => "Larry", "files" => "contents"}])
      data.should be_nil
    end

    it "raises ArgumentErrors if params is not a Hash" do
      lambda {
        build_multipart("foo=bar")
      }.should raise_error(ArgumentError, "value must be a Hash")
    end

    def multipart_file(name)
      File.join(File.dirname(__FILE__), "..", "..", "fixtures", name.to_s)
    end
  end
end
