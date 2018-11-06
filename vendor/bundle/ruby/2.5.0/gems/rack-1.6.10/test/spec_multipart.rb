require 'rack/utils'
require 'rack/mock'

describe Rack::Multipart do
  def multipart_fixture(name, boundary = "AaB03x")
    file = multipart_file(name)
    data = File.open(file, 'rb') { |io| io.read }

    type = "multipart/form-data; boundary=#{boundary}"
    length = data.respond_to?(:bytesize) ? data.bytesize : data.size

    { "CONTENT_TYPE" => type,
      "CONTENT_LENGTH" => length.to_s,
      :input => StringIO.new(data) }
  end

  def multipart_file(name)
    File.join(File.dirname(__FILE__), "multipart", name.to_s)
  end

  should "return nil if content type is not multipart" do
    env = Rack::MockRequest.env_for("/",
            "CONTENT_TYPE" => 'application/x-www-form-urlencoded')
    Rack::Multipart.parse_multipart(env).should.equal nil
  end

  should "parse multipart content when content type present but filename is not" do
    env = Rack::MockRequest.env_for("/", multipart_fixture(:content_type_and_no_filename))
    params = Rack::Multipart.parse_multipart(env)
    params["text"].should.equal "contents"
  end

  if "<3".respond_to?(:force_encoding)
  should "set US_ASCII encoding based on charset" do
    env = Rack::MockRequest.env_for("/", multipart_fixture(:content_type_and_no_filename))
    params = Rack::Multipart.parse_multipart(env)
    params["text"].encoding.should.equal Encoding::US_ASCII

    # I'm not 100% sure if making the param name encoding match the
    # Content-Type charset is the right thing to do.  We should revisit this.
    params.keys.each do |key|
      key.encoding.should.equal Encoding::US_ASCII
    end
  end

  should "set BINARY encoding on things without content type" do
    env = Rack::MockRequest.env_for("/", multipart_fixture(:none))
    params = Rack::Multipart.parse_multipart(env)
    params["submit-name"].encoding.should.equal Encoding::UTF_8
  end

  should "set UTF8 encoding on names of things without content type" do
    env = Rack::MockRequest.env_for("/", multipart_fixture(:none))
    params = Rack::Multipart.parse_multipart(env)
    params.keys.each do |key|
      key.encoding.should.equal Encoding::UTF_8
    end
  end

  should "default text to UTF8" do
    env = Rack::MockRequest.env_for("/", multipart_fixture(:text))
    params = Rack::Multipart.parse_multipart(env)
    params['submit-name'].encoding.should.equal Encoding::UTF_8
    params['submit-name-with-content'].encoding.should.equal Encoding::UTF_8
    params.keys.each do |key|
      key.encoding.should.equal Encoding::UTF_8
    end
  end
  end

  should "raise RangeError if the key space is exhausted" do
    env = Rack::MockRequest.env_for("/", multipart_fixture(:content_type_and_no_filename))

    old, Rack::Utils.key_space_limit = Rack::Utils.key_space_limit, 1
    begin
      lambda { Rack::Multipart.parse_multipart(env) }.should.raise(RangeError)
    ensure
      Rack::Utils.key_space_limit = old
    end
  end

  should "parse multipart form webkit style" do
    env = Rack::MockRequest.env_for '/', multipart_fixture(:webkit)
    env['CONTENT_TYPE'] = "multipart/form-data; boundary=----WebKitFormBoundaryWLHCs9qmcJJoyjKR"
    params = Rack::Multipart.parse_multipart(env)
    params['profile']['bio'].should.include 'hello'
  end

  should "reject insanely long boundaries" do
    # using a pipe since a tempfile can use up too much space
    rd, wr = IO.pipe

    # we only call rewind once at start, so make sure it succeeds
    # and doesn't hit ESPIPE
    def rd.rewind; end
    wr.sync = true

    # mock out length to make this pipe look like a Tempfile
    def rd.length
      1024 * 1024 * 8
    end

    # write to a pipe in a background thread, this will write a lot
    # unless Rack (properly) shuts down the read end
    thr = Thread.new do
      begin
        wr.write("--AaB03x")

        # make the initial boundary a few gigs long
        longer = "0123456789" * 1024 * 1024
        (1024 * 1024).times { wr.write(longer) }

        wr.write("\r\n")
        wr.write('Content-Disposition: form-data; name="a"; filename="a.txt"')
        wr.write("\r\n")
        wr.write("Content-Type: text/plain\r\n")
        wr.write("\r\na")
        wr.write("--AaB03x--\r\n")
        wr.close
      rescue => err # this is EPIPE if Rack shuts us down
        err
      end
    end

    fixture = {
      "CONTENT_TYPE" => "multipart/form-data; boundary=AaB03x",
      "CONTENT_LENGTH" => rd.length.to_s,
      :input => rd,
    }

    env = Rack::MockRequest.env_for '/', fixture
    lambda {
      Rack::Multipart.parse_multipart(env)
    }.should.raise(EOFError)
    rd.close

    err = thr.value
    err.should.be.instance_of Errno::EPIPE
    wr.close
  end

  should "parse multipart upload with text file" do
    env = Rack::MockRequest.env_for("/", multipart_fixture(:text))
    params = Rack::Multipart.parse_multipart(env)
    params["submit-name"].should.equal "Larry"
    params["submit-name-with-content"].should.equal "Berry"
    params["files"][:type].should.equal "text/plain"
    params["files"][:filename].should.equal "file1.txt"
    params["files"][:head].should.equal "Content-Disposition: form-data; " +
      "name=\"files\"; filename=\"file1.txt\"\r\n" +
      "Content-Type: text/plain\r\n"
    params["files"][:name].should.equal "files"
    params["files"][:tempfile].read.should.equal "contents"
  end

  should "preserve extension in the created tempfile" do
    env = Rack::MockRequest.env_for("/", multipart_fixture(:text))
    params = Rack::Multipart.parse_multipart(env)
    File.extname(params["files"][:tempfile].path).should.equal ".txt"
  end

  should "parse multipart upload with text file with no name field" do
    env = Rack::MockRequest.env_for("/", multipart_fixture(:filename_and_no_name))
    params = Rack::Multipart.parse_multipart(env)
    params["file1.txt"][:type].should.equal "text/plain"
    params["file1.txt"][:filename].should.equal "file1.txt"
    params["file1.txt"][:head].should.equal "Content-Disposition: form-data; " +
      "filename=\"file1.txt\"\r\n" +
      "Content-Type: text/plain\r\n"
    params["file1.txt"][:name].should.equal "file1.txt"
    params["file1.txt"][:tempfile].read.should.equal "contents"
  end

  should "parse multipart upload file using custom tempfile class" do
    env = Rack::MockRequest.env_for("/", multipart_fixture(:text))
    my_tempfile = ""
    env['rack.multipart.tempfile_factory'] = lambda { |filename, content_type| my_tempfile }
    params = Rack::Multipart.parse_multipart(env)
    params["files"][:tempfile].object_id.should.equal my_tempfile.object_id
    my_tempfile.should.equal "contents"
  end

  should "parse multipart upload with nested parameters" do
    env = Rack::MockRequest.env_for("/", multipart_fixture(:nested))
    params = Rack::Multipart.parse_multipart(env)
    params["foo"]["submit-name"].should.equal "Larry"
    params["foo"]["files"][:type].should.equal "text/plain"
    params["foo"]["files"][:filename].should.equal "file1.txt"
    params["foo"]["files"][:head].should.equal "Content-Disposition: form-data; " +
      "name=\"foo[files]\"; filename=\"file1.txt\"\r\n" +
      "Content-Type: text/plain\r\n"
    params["foo"]["files"][:name].should.equal "foo[files]"
    params["foo"]["files"][:tempfile].read.should.equal "contents"
  end

  should "parse multipart upload with binary file" do
    env = Rack::MockRequest.env_for("/", multipart_fixture(:binary))
    params = Rack::Multipart.parse_multipart(env)
    params["submit-name"].should.equal "Larry"
    params["files"][:type].should.equal "image/png"
    params["files"][:filename].should.equal "rack-logo.png"
    params["files"][:head].should.equal "Content-Disposition: form-data; " +
      "name=\"files\"; filename=\"rack-logo.png\"\r\n" +
      "Content-Type: image/png\r\n"
    params["files"][:name].should.equal "files"
    params["files"][:tempfile].read.length.should.equal 26473
  end

  should "parse multipart upload with empty file" do
    env = Rack::MockRequest.env_for("/", multipart_fixture(:empty))
    params = Rack::Multipart.parse_multipart(env)
    params["submit-name"].should.equal "Larry"
    params["files"][:type].should.equal "text/plain"
    params["files"][:filename].should.equal "file1.txt"
    params["files"][:head].should.equal "Content-Disposition: form-data; " +
      "name=\"files\"; filename=\"file1.txt\"\r\n" +
      "Content-Type: text/plain\r\n"
    params["files"][:name].should.equal "files"
    params["files"][:tempfile].read.should.equal ""
  end

  should "parse multipart upload with filename with semicolons" do
    env = Rack::MockRequest.env_for("/", multipart_fixture(:semicolon))
    params = Rack::Multipart.parse_multipart(env)
    params["files"][:type].should.equal "text/plain"
    params["files"][:filename].should.equal "fi;le1.txt"
    params["files"][:head].should.equal "Content-Disposition: form-data; " +
      "name=\"files\"; filename=\"fi;le1.txt\"\r\n" +
      "Content-Type: text/plain\r\n"
    params["files"][:name].should.equal "files"
    params["files"][:tempfile].read.should.equal "contents"
  end

  should "parse multipart upload with filename with invalid characters" do
    env = Rack::MockRequest.env_for("/", multipart_fixture(:invalid_character))
    params = Rack::Multipart.parse_multipart(env)
    params["files"][:type].should.equal "text/plain"
    params["files"][:filename].should.match(/invalid/)
    head = "Content-Disposition: form-data; " +
      "name=\"files\"; filename=\"invalid\xC3.txt\"\r\n" +
      "Content-Type: text/plain\r\n"
    head = head.force_encoding("ASCII-8BIT") if head.respond_to?(:force_encoding)
    params["files"][:head].should.equal head
    params["files"][:name].should.equal "files"
    params["files"][:tempfile].read.should.equal "contents"
  end

  should "not include file params if no file was selected" do
    env = Rack::MockRequest.env_for("/", multipart_fixture(:none))
    params = Rack::Multipart.parse_multipart(env)
    params["submit-name"].should.equal "Larry"
    params["files"].should.equal nil
    params.keys.should.not.include "files"
  end

  should "parse multipart/mixed" do
    env = Rack::MockRequest.env_for("/", multipart_fixture(:mixed_files))
    params = Rack::Utils::Multipart.parse_multipart(env)
    params["foo"].should.equal "bar"
    params["files"].should.be.instance_of String
    params["files"].size.should.equal 252
  end

  should "parse multipart form with a null byte in the filename" do
    env = Rack::MockRequest.env_for '/', multipart_fixture(:filename_with_null_byte)
    params = Rack::Multipart.parse_multipart(env)
    if "<3".respond_to?(:encoding)
      params["files"][:filename].should.equal "flowers.exe\u0000.jpg"
    else
      params["files"][:filename].should.equal "flowers.exe\000.jpg"
    end
  end

  should "parse multipart/mixed" do
    env = Rack::MockRequest.env_for("/", multipart_fixture(:mixed_files))
    params = Rack::Utils::Multipart.parse_multipart(env)
    params["foo"].should.equal "bar"
    params["files"].should.be.instance_of String
    params["files"].size.should.equal 252
  end

  should "parse IE multipart upload and clean up filename" do
    env = Rack::MockRequest.env_for("/", multipart_fixture(:ie))
    params = Rack::Multipart.parse_multipart(env)
    params["files"][:type].should.equal "text/plain"
    params["files"][:filename].should.equal "file1.txt"
    params["files"][:head].should.equal "Content-Disposition: form-data; " +
      "name=\"files\"; " +
      'filename="C:\Documents and Settings\Administrator\Desktop\file1.txt"' +
      "\r\nContent-Type: text/plain\r\n"
    params["files"][:name].should.equal "files"
    params["files"][:tempfile].read.should.equal "contents"
  end

  should "parse filename and modification param" do
    env = Rack::MockRequest.env_for("/", multipart_fixture(:filename_and_modification_param))
    params = Rack::Multipart.parse_multipart(env)
    params["files"][:type].should.equal "image/jpeg"
    params["files"][:filename].should.equal "genome.jpeg"
    params["files"][:head].should.equal "Content-Type: image/jpeg\r\n" +
      "Content-Disposition: attachment; " +
      "name=\"files\"; " +
      "filename=genome.jpeg; " +
      "modification-date=\"Wed, 12 Feb 1997 16:29:51 -0500\";\r\n" +
      "Content-Description: a complete map of the human genome\r\n"
    params["files"][:name].should.equal "files"
    params["files"][:tempfile].read.should.equal "contents"
  end

  should "parse filename with escaped quotes" do
    env = Rack::MockRequest.env_for("/", multipart_fixture(:filename_with_escaped_quotes))
    params = Rack::Multipart.parse_multipart(env)
    params["files"][:type].should.equal "application/octet-stream"
    params["files"][:filename].should.equal "escape \"quotes"
    params["files"][:head].should.equal "Content-Disposition: form-data; " +
      "name=\"files\"; " +
      "filename=\"escape \\\"quotes\"\r\n" +
      "Content-Type: application/octet-stream\r\n"
    params["files"][:name].should.equal "files"
    params["files"][:tempfile].read.should.equal "contents"
  end

  should "parse filename with percent escaped quotes" do
    env = Rack::MockRequest.env_for("/", multipart_fixture(:filename_with_percent_escaped_quotes))
    params = Rack::Multipart.parse_multipart(env)
    params["files"][:type].should.equal "application/octet-stream"
    params["files"][:filename].should.equal "escape \"quotes"
    params["files"][:head].should.equal "Content-Disposition: form-data; " +
      "name=\"files\"; " +
      "filename=\"escape %22quotes\"\r\n" +
      "Content-Type: application/octet-stream\r\n"
    params["files"][:name].should.equal "files"
    params["files"][:tempfile].read.should.equal "contents"
  end

  should "parse filename with unescaped quotes" do
    env = Rack::MockRequest.env_for("/", multipart_fixture(:filename_with_unescaped_quotes))
    params = Rack::Multipart.parse_multipart(env)
    params["files"][:type].should.equal "application/octet-stream"
    params["files"][:filename].should.equal "escape \"quotes"
    params["files"][:head].should.equal "Content-Disposition: form-data; " +
      "name=\"files\"; " +
      "filename=\"escape \"quotes\"\r\n" +
      "Content-Type: application/octet-stream\r\n"
    params["files"][:name].should.equal "files"
    params["files"][:tempfile].read.should.equal "contents"
  end

  should "parse filename with escaped quotes and modification param" do
    env = Rack::MockRequest.env_for("/", multipart_fixture(:filename_with_escaped_quotes_and_modification_param))
    params = Rack::Multipart.parse_multipart(env)
    params["files"][:type].should.equal "image/jpeg"
    params["files"][:filename].should.equal "\"human\" genome.jpeg"
    params["files"][:head].should.equal "Content-Type: image/jpeg\r\n" +
      "Content-Disposition: attachment; " +
      "name=\"files\"; " +
      "filename=\"\"human\" genome.jpeg\"; " +
      "modification-date=\"Wed, 12 Feb 1997 16:29:51 -0500\";\r\n" +
      "Content-Description: a complete map of the human genome\r\n"
    params["files"][:name].should.equal "files"
    params["files"][:tempfile].read.should.equal "contents"
  end

  should "parse filename with unescaped percentage characters" do
    env = Rack::MockRequest.env_for("/", multipart_fixture(:filename_with_unescaped_percentages, "----WebKitFormBoundary2NHc7OhsgU68l3Al"))
    params = Rack::Multipart.parse_multipart(env)
    files = params["document"]["attachment"]
    files[:type].should.equal "image/jpeg"
    files[:filename].should.equal "100% of a photo.jpeg"
    files[:head].should.equal <<-MULTIPART
Content-Disposition: form-data; name="document[attachment]"; filename="100% of a photo.jpeg"\r
Content-Type: image/jpeg\r
    MULTIPART

    files[:name].should.equal "document[attachment]"
    files[:tempfile].read.should.equal "contents"
  end

  should "parse filename with unescaped percentage characters that look like partial hex escapes" do
    env = Rack::MockRequest.env_for("/", multipart_fixture(:filename_with_unescaped_percentages2, "----WebKitFormBoundary2NHc7OhsgU68l3Al"))
    params = Rack::Multipart.parse_multipart(env)
    files = params["document"]["attachment"]
    files[:type].should.equal "image/jpeg"
    files[:filename].should.equal "100%a"
    files[:head].should.equal <<-MULTIPART
Content-Disposition: form-data; name="document[attachment]"; filename="100%a"\r
Content-Type: image/jpeg\r
    MULTIPART

    files[:name].should.equal "document[attachment]"
    files[:tempfile].read.should.equal "contents"
  end

  should "parse filename with unescaped percentage characters that look like partial hex escapes" do
    env = Rack::MockRequest.env_for("/", multipart_fixture(:filename_with_unescaped_percentages3, "----WebKitFormBoundary2NHc7OhsgU68l3Al"))
    params = Rack::Multipart.parse_multipart(env)
    files = params["document"]["attachment"]
    files[:type].should.equal "image/jpeg"
    files[:filename].should.equal "100%"
    files[:head].should.equal <<-MULTIPART
Content-Disposition: form-data; name="document[attachment]"; filename="100%"\r
Content-Type: image/jpeg\r
    MULTIPART

    files[:name].should.equal "document[attachment]"
    files[:tempfile].read.should.equal "contents"
  end

  it "rewinds input after parsing upload" do
    options = multipart_fixture(:text)
    input = options[:input]
    env = Rack::MockRequest.env_for("/", options)
    params = Rack::Multipart.parse_multipart(env)
    params["submit-name"].should.equal "Larry"
    params["files"][:filename].should.equal "file1.txt"
    input.read.length.should.equal 307
  end

  it "builds multipart body" do
    files = Rack::Multipart::UploadedFile.new(multipart_file("file1.txt"))
    data  = Rack::Multipart.build_multipart("submit-name" => "Larry", "files" => files)

    options = {
      "CONTENT_TYPE" => "multipart/form-data; boundary=AaB03x",
      "CONTENT_LENGTH" => data.length.to_s,
      :input => StringIO.new(data)
    }
    env = Rack::MockRequest.env_for("/", options)
    params = Rack::Multipart.parse_multipart(env)
    params["submit-name"].should.equal "Larry"
    params["files"][:filename].should.equal "file1.txt"
    params["files"][:tempfile].read.should.equal "contents"
  end

  it "builds nested multipart body" do
    files = Rack::Multipart::UploadedFile.new(multipart_file("file1.txt"))
    data  = Rack::Multipart.build_multipart("people" => [{"submit-name" => "Larry", "files" => files}])

    options = {
      "CONTENT_TYPE" => "multipart/form-data; boundary=AaB03x",
      "CONTENT_LENGTH" => data.length.to_s,
      :input => StringIO.new(data)
    }
    env = Rack::MockRequest.env_for("/", options)
    params = Rack::Multipart.parse_multipart(env)
    params["people"][0]["submit-name"].should.equal "Larry"
    params["people"][0]["files"][:filename].should.equal "file1.txt"
    params["people"][0]["files"][:tempfile].read.should.equal "contents"
  end

  it "can parse fields that end at the end of the buffer" do
    input = File.read(multipart_file("bad_robots"))

    req = Rack::Request.new Rack::MockRequest.env_for("/",
                      "CONTENT_TYPE" => "multipart/form-data, boundary=1yy3laWhgX31qpiHinh67wJXqKalukEUTvqTzmon",
                      "CONTENT_LENGTH" => input.size,
                      :input => input)

    req.POST['file.path'].should.equal "/var/tmp/uploads/4/0001728414"
    req.POST['addresses'].should.not.equal nil
  end

  it "builds complete params with the chunk size of 16384 slicing exactly on boundary" do
    begin
      previous_limit = Rack::Utils.multipart_part_limit
      Rack::Utils.multipart_part_limit = 256

      data = File.open(multipart_file("fail_16384_nofile"), 'rb') { |f| f.read }.gsub(/\n/, "\r\n")
      options = {
        "CONTENT_TYPE" => "multipart/form-data; boundary=----WebKitFormBoundaryWsY0GnpbI5U7ztzo",
        "CONTENT_LENGTH" => data.length.to_s,
        :input => StringIO.new(data)
      }
      env = Rack::MockRequest.env_for("/", options)
      params = Rack::Multipart.parse_multipart(env)

      params.should.not.equal nil
      params.keys.should.include "AAAAAAAAAAAAAAAAAAA"
      params["AAAAAAAAAAAAAAAAAAA"].keys.should.include "PLAPLAPLA_MEMMEMMEMM_ATTRATTRER"
      params["AAAAAAAAAAAAAAAAAAA"]["PLAPLAPLA_MEMMEMMEMM_ATTRATTRER"].keys.should.include "new"
      params["AAAAAAAAAAAAAAAAAAA"]["PLAPLAPLA_MEMMEMMEMM_ATTRATTRER"]["new"].keys.should.include "-2"
      params["AAAAAAAAAAAAAAAAAAA"]["PLAPLAPLA_MEMMEMMEMM_ATTRATTRER"]["new"]["-2"].keys.should.include "ba_unit_id"
      params["AAAAAAAAAAAAAAAAAAA"]["PLAPLAPLA_MEMMEMMEMM_ATTRATTRER"]["new"]["-2"]["ba_unit_id"].should.equal "1017"
    ensure
      Rack::Utils.multipart_part_limit = previous_limit
    end
  end

 should "not reach a multi-part limit" do
    begin
      previous_limit = Rack::Utils.multipart_part_limit
      Rack::Utils.multipart_part_limit = 4

      env = Rack::MockRequest.env_for '/', multipart_fixture(:three_files_three_fields)
      params = Rack::Multipart.parse_multipart(env)
      params['reply'].should.equal 'yes'
      params['to'].should.equal 'people'
      params['from'].should.equal 'others'
    ensure
      Rack::Utils.multipart_part_limit = previous_limit
    end
  end

  should "reach a multipart limit" do
    begin
      previous_limit = Rack::Utils.multipart_part_limit
      Rack::Utils.multipart_part_limit = 3

      env = Rack::MockRequest.env_for '/', multipart_fixture(:three_files_three_fields)
      lambda { Rack::Multipart.parse_multipart(env) }.should.raise(Rack::Multipart::MultipartPartLimitError)
    ensure
      Rack::Utils.multipart_part_limit = previous_limit
    end
  end

  should "return nil if no UploadedFiles were used" do
    data = Rack::Multipart.build_multipart("people" => [{"submit-name" => "Larry", "files" => "contents"}])
    data.should.equal nil
  end

  should "raise ArgumentError if params is not a Hash" do
    lambda { Rack::Multipart.build_multipart("foo=bar") }.
      should.raise(ArgumentError).
      message.should.equal "value must be a Hash"
  end

  it "can parse fields with a content type" do
    data = <<-EOF
--1yy3laWhgX31qpiHinh67wJXqKalukEUTvqTzmon\r
Content-Disposition: form-data; name="description"\r
Content-Type: text/plain"\r
\r
Very very blue\r
--1yy3laWhgX31qpiHinh67wJXqKalukEUTvqTzmon--\r
EOF
    options = {
      "CONTENT_TYPE" => "multipart/form-data; boundary=1yy3laWhgX31qpiHinh67wJXqKalukEUTvqTzmon",
      "CONTENT_LENGTH" => data.length.to_s,
      :input => StringIO.new(data)
    }
    env = Rack::MockRequest.env_for("/", options)
    params = Rack::Utils::Multipart.parse_multipart(env)

    params.should.equal({"description"=>"Very very blue"})
  end

  should "parse multipart upload with no content-length header" do
    env = Rack::MockRequest.env_for '/', multipart_fixture(:webkit)
    env['CONTENT_TYPE'] = "multipart/form-data; boundary=----WebKitFormBoundaryWLHCs9qmcJJoyjKR"
    env.delete 'CONTENT_LENGTH'
    params = Rack::Multipart.parse_multipart(env)
    params['profile']['bio'].should.include 'hello'
  end

  should "parse very long unquoted multipart file names" do
    data = <<-EOF
--AaB03x\r
Content-Type: text/plain\r
Content-Disposition: attachment; name=file; filename=#{'long' * 100}\r
\r
contents\r
--AaB03x--\r
    EOF

    options = {
      "CONTENT_TYPE" => "multipart/form-data; boundary=AaB03x",
      "CONTENT_LENGTH" => data.length.to_s,
      :input => StringIO.new(data)
    }
    env = Rack::MockRequest.env_for("/", options)
    params = Rack::Utils::Multipart.parse_multipart(env)

    params["file"][:filename].should.equal('long' * 100)
  end

  should "support mixed case metadata" do
    file = multipart_file(:text)
    data = File.open(file, 'rb') { |io| io.read }

    type = "Multipart/Form-Data; Boundary=AaB03x"
    length = data.respond_to?(:bytesize) ? data.bytesize : data.size

    e = { "CONTENT_TYPE" => type,
      "CONTENT_LENGTH" => length.to_s,
      :input => StringIO.new(data) }

    env = Rack::MockRequest.env_for("/", e)
    params = Rack::Multipart.parse_multipart(env)
    params["submit-name"].should.equal "Larry"
    params["submit-name-with-content"].should.equal "Berry"
    params["files"][:type].should.equal "text/plain"
    params["files"][:filename].should.equal "file1.txt"
    params["files"][:head].should.equal "Content-Disposition: form-data; " +
      "name=\"files\"; filename=\"file1.txt\"\r\n" +
      "Content-Type: text/plain\r\n"
    params["files"][:name].should.equal "files"
    params["files"][:tempfile].read.should.equal "contents"
  end

end
