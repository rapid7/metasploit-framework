require 'spec_helper'

load Metasploit::Framework.root.join('tools/exploit/jsobfu.rb').to_path

require 'stringio'

RSpec.describe Jsobfu do

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
      let(:default_opts) {
        { :input => fname, :iteration => 1 }
      }

      before(:example) do
        allow(Jsobfu::OptsConsole).to receive(:parse).with(any_args).and_return(default_opts)
        allow(File).to receive(:open).with(fname, 'rb').and_yield(StringIO.new(js))
        @out = $stdout
        $stdout = StringIO.new
        $stdout.string = ''
      end

      after(:example) do
        $stdout = @out
      end

      context 'when a javascript file is given' do
        it 'returns an String' do
          subject.run
          expect($stdout.string).to be_a(String)
        end

        it 'returns a non empty String' do
          subject.run
          expect($stdout.string).not_to be_empty
        end

        it 'returns an String different than the original' do
          subject.run
          expect($stdout.string).not_to eq(js)
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
