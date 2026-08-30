require 'rex'

RSpec.describe Msf::Util::JavaDeserialization::BeanFactory do
  describe '#generate' do
    it 'generates the correct gadget chain' do
      # this is a quick but important check to ensure consistency of the
      # serialized payloads which are deterministic
      table = {
        'bash'       => '9e66df5e4e57e473e6f78e55cbf95708b3ecdf6b',
        'cmd'        => '534cb3b84daf2290e87f7c325dc2aa0adddcd9b5',
        'powershell' => '030fbad1d4fbdc7f49067947273fb295c4a5dc24',
        nil          => '9a9c678d2073994cec42b1ba74774a345687bcc3'
      }
      table.each do |shell, correct_digest|
        stream = Msf::Util::JavaDeserialization::BeanFactory.generate('ping 127.0.0.1', shell: shell)
        expect(stream).to be_kind_of String
        real_digest = OpenSSL::Digest::SHA1.hexdigest(stream)
        expect(real_digest).to eq correct_digest
      end
    end
  end
end
