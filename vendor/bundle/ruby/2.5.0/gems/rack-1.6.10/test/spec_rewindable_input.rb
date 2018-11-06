require 'stringio'
require 'rack/rewindable_input'

shared "a rewindable IO object" do
  before do
    @rio = Rack::RewindableInput.new(@io)
  end

  should "be able to handle to read()" do
    @rio.read.should.equal "hello world"
  end

  should "be able to handle to read(nil)" do
    @rio.read(nil).should.equal "hello world"
  end

  should "be able to handle to read(length)" do
    @rio.read(1).should.equal "h"
  end

  should "be able to handle to read(length, buffer)" do
    buffer = ""
    result = @rio.read(1, buffer)
    result.should.equal "h"
    result.object_id.should.equal buffer.object_id
  end

  should "be able to handle to read(nil, buffer)" do
    buffer = ""
    result = @rio.read(nil, buffer)
    result.should.equal "hello world"
    result.object_id.should.equal buffer.object_id
  end

  should "rewind to the beginning when #rewind is called" do
    @rio.read(1)
    @rio.rewind
    @rio.read.should.equal "hello world"
  end

  should "be able to handle gets" do
    @rio.gets.should == "hello world"
  end

  should "be able to handle each" do
    array = []
    @rio.each do |data|
      array << data
    end
    array.should.equal(["hello world"])
  end

  should "not buffer into a Tempfile if no data has been read yet" do
    @rio.instance_variable_get(:@rewindable_io).should.be.nil
  end

  should "buffer into a Tempfile when data has been consumed for the first time" do
    @rio.read(1)
    tempfile = @rio.instance_variable_get(:@rewindable_io)
    tempfile.should.not.be.nil
    @rio.read(1)
    tempfile2 = @rio.instance_variable_get(:@rewindable_io)
    tempfile2.path.should == tempfile.path
  end

  should "close the underlying tempfile upon calling #close" do
    @rio.read(1)
    tempfile = @rio.instance_variable_get(:@rewindable_io)
    @rio.close
    tempfile.should.be.closed
  end

  should "be possible to call #close when no data has been buffered yet" do
    lambda{ @rio.close }.should.not.raise
  end

  should "be possible to call #close multiple times" do
    lambda{
      @rio.close
      @rio.close
    }.should.not.raise
  end

  @rio.close
  @rio = nil
end

describe Rack::RewindableInput do
  describe "given an IO object that is already rewindable" do
    before do
      @io = StringIO.new("hello world")
    end

    behaves_like "a rewindable IO object"
  end

  describe "given an IO object that is not rewindable" do
    before do
      @io = StringIO.new("hello world")
      @io.instance_eval do
        undef :rewind
      end
    end

    behaves_like "a rewindable IO object"
  end

  describe "given an IO object whose rewind method raises Errno::ESPIPE" do
    before do
      @io = StringIO.new("hello world")
      def @io.rewind
        raise Errno::ESPIPE, "You can't rewind this!"
      end
    end

    behaves_like "a rewindable IO object"
  end
end
