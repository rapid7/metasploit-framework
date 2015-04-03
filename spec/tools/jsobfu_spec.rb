load Metasploit::Framework.root.join('tools/jsobfu.rb').to_path

require 'stringio'

describe Jsobfu do

  let(:fname) {
    'test.js'
  }

  let(:js) {
    %Q|alert("test");|
  }

  describe Jsobfu::Driver do

    subject do
      Jsobfu::Driver.new
    end

    describe '#run' do

      def get_stdout(&block)
        out = $stdout
        $stdout = fake = StringIO.new
        begin
          yield
        ensure
          $stdout = out
        end
        fake.string
      end

      let(:default_opts) {
        { :input => fname, :iteration => 1 }
      }

      before(:each) do
        allow(Jsobfu::OptsConsole).to receive(:parse).with(any_args).and_return(default_opts)
        allow(File).to receive(:open).with(fname, 'rb').and_yield(StringIO.new(js))
      end

      context 'when a javascript file is given' do
        it 'returns the obfuscated version of the js code' do
          output = get_stdout { subject.run }
          expect(output).to include('String.fromCharCode')
        end
      end

    end
  end


  describe Jsobfu::OptsConsole do
    subject do
      Jsobfu::OptsConsole
    end

    context 'when no options are given' do
      it 'raises OptionParser::MissingArgument' do
        expect{subject.parse([])}.to raise_error(OptionParser::MissingArgument)
      end
    end

    context 'when -t isn\'t a number' do
      it 'raises OptionParser::MissingArgument' do
        args = "-i #{fname} -t NaN".split
        expect{subject.parse(args)}.to raise_error(OptionParser::InvalidOption)
      end
    end
  end

end
