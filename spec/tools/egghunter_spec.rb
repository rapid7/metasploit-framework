load Metasploit::Framework.root.join('tools/egghunter.rb').to_path

require 'rex/proto/http/response'
require 'stringio'

describe Egghunter do

  subject do
    Egghunter::Driver.new
  end

  describe '#run' do

    context 'when the platform is windows' do
      it 'returns a windows egghunter' do
      end
    end

    context 'when the platform is linux' do
      it 'returns a linux egghunter' do
      end
    end

    context 'when the output format is java' do
      it 'returns java format egghunter' do
      end
    end

    context 'when the egg is WOOT' do
      it 'includes W00TW00T in the egghunter' do
      end
    end

  end
end