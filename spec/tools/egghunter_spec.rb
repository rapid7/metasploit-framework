load Metasploit::Framework.root.join('tools/egghunter.rb').to_path

require 'rex/proto/http/response'
require 'stringio'

describe Egghunter do
  subject do
    Egghunter::Driver.new
  end

  describe '#run' do
  end

end