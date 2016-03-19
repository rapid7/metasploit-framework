load Metasploit::Framework.root.join('tools/exploit/egghunter.rb').to_path
require 'spec_helper'

RSpec.describe Egghunter do

  describe Egghunter::Driver do

    subject do
      Egghunter::Driver.new
    end

    let(:egg) {
      'W00T'
    }

    describe '#run' do

      let(:default_opts) {
        { :platform => 'windows', :format => 'c', :eggtag => egg, :arch => 'x86' }
      }

      before(:example) do
        allow(Egghunter::OptsConsole).to receive(:parse).with(any_args).and_return(options)
      end

      context 'when the platform is windows' do
        let(:options) { default_opts }

        it 'returns a windows egghunter' do
          output = get_stdout { subject.run }
          expect(output).to include("\\x66\\x81\\xca\\xff")
        end
      end

      context 'when the platform is linux' do
        let(:options) do
          { :platform => 'linux', :format => 'c', :eggtag => egg, :arch => 'x86' }
        end

        it 'returns a linux egghunter' do
          output = get_stdout { subject.run }
          expect(output).to include("\\xfc\\x66\\x81\\xc9\\xff")
        end
      end

      context 'when the egg is WOOT' do
        let(:options) { default_opts }

        it 'includes W00T in the egghunter' do
          output = get_stdout { subject.run }
          expect(output).to include("\\x57\\x30\\x30\\x54")
        end
      end
    end
  end


  describe Egghunter::OptsConsole do
    subject do
      Egghunter::OptsConsole
    end

    context 'when no options are given' do
      it 'raises OptionParser::MissingArgument' do
        expect{subject.parse([])}.to raise_error(OptionParser::MissingArgument)
      end
    end

    context 'when no format is specified and --list-formats isn\'t used' do
      it 'raises OptionParser::MissingArgument' do
        args = '-e AAAA'.split
        expect{subject.parse(args)}.to raise_error(OptionParser::MissingArgument)
      end
    end

    context 'when no egg is specified and --list-formats isn\'t used' do
      it 'raises OptionParser::MissingArgument' do
        args = '-f python'.split
        expect{subject.parse(args)}.to raise_error(OptionParser::MissingArgument)
      end
    end

    context 'when :depsize is a string' do
      it 'raises OptionParser::InvalidOption' do
        args = '-e AAAA -f c --depsize STRING'.split
        expect{subject.parse(args)}.to raise_error(OptionParser::InvalidOption)
      end
    end
  end

end
