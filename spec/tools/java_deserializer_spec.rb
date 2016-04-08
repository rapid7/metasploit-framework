require 'rex/java'
require 'stringio'

load Metasploit::Framework.root.join('tools/exploit/java_deserializer.rb').to_path

RSpec.describe JavaDeserializer do

  before(:context) do
    @out = $stdout
    @err = $stderr

    $stdout = StringIO.new
    $stderr = StringIO.new
  end

  after(:context) do
    $stdout = @out
    $stderr = @err
  end

  subject(:deserializer) do
    described_class.new
  end

  let(:valid_stream) do
    "\xac\xed\x00\x05\x75\x72\x00\x02" +
    "\x5b\x43\xb0\x26\x66\xb0\xe2\x5d" +
    "\x84\xac\x02\x00\x00\x78\x70\x00" +
    "\x00\x00\x02\x00\x61\x00\x62"
  end

  describe ".new" do
    it "returns a JavaDeserializer instance" do
      expect(deserializer).to be_a(JavaDeserializer)
    end

    it "initializes file to nil" do
      expect(deserializer.file).to be_nil
    end
  end

  describe "#run" do
    context "when file is nil" do
      it "returns nil" do
        expect(deserializer.run).to be_nil
      end
    end

    context "when file contains a valid stream" do
      before(:example) do
        $stdout.string = ''
      end

      context "when no options" do
        it "prints the stream contents" do
          expect(File).to receive(:new) do
            contents = valid_stream
            StringIO.new(contents)
          end
          deserializer.file = 'sample'
          deserializer.run
          expect($stdout.string).to include('[7e0001] NewArray { char, ["97", "98"] }')
        end
      end

      context "when :array in options" do
        it "prints the array contents" do
          expect(File).to receive(:new) do
            contents = valid_stream
            StringIO.new(contents)
          end
          deserializer.file = 'sample'
          deserializer.run({:array => '0'})
          expect($stdout.string).to include('Array Type: char')
        end
      end
    end

    context "when file contains an invalid stream" do
      it "prints the error while deserializing" do
        expect(File).to receive(:new) do
          contents = 'invalid_stream'
          StringIO.new(contents)
        end
        deserializer.file = 'sample'
        deserializer.run
        expect($stdout.string).to include('[-] Failed to unserialize Stream')
      end
    end
  end
end