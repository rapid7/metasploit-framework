# frozen_string_literal: true

require 'spec_helper'

RSpec.describe Msf::Auxiliary::PasswordCracker do
  class DummyPasswordCracker
    include Msf::Auxiliary::PasswordCracker

    attr_accessor :datastore, :framework

    def initialize
      self.datastore = {}
      db = Struct.new(:active).new(true)
      self.framework = Struct.new(:db).new(db)
    end

    def fail_with(_type, message)
      raise RuntimeError, message
    end
  end

  subject(:helper) { DummyPasswordCracker.new }

  describe '#resolve_cracking_application' do
    it 'infers john from CRACKER_PATH when ACTION is auto' do
      helper.datastore['CRACKER_PATH'] = '/opt/john/run/john'
      cracker = Metasploit::Framework::PasswordCracker::Cracker.new(cracker_path: helper.datastore['CRACKER_PATH'])

      expect(helper.resolve_cracking_application('auto', cracker)).to eq('john')
    end

    it 'infers hashcat from CRACKER_PATH when ACTION is auto' do
      helper.datastore['CRACKER_PATH'] = '/opt/hashcat/hashcat'
      cracker = Metasploit::Framework::PasswordCracker::Cracker.new(cracker_path: helper.datastore['CRACKER_PATH'])

      expect(helper.resolve_cracking_application('auto', cracker)).to eq('hashcat')
    end

    it 'raises a BadConfig style error when CRACKER_PATH is unknown with ACTION auto' do
      helper.datastore['CRACKER_PATH'] = '/opt/tools/myawesomecracker'
      cracker = Metasploit::Framework::PasswordCracker::Cracker.new(cracker_path: helper.datastore['CRACKER_PATH'])

      expect {
        helper.resolve_cracking_application('auto', cracker)
      }.to raise_error(RuntimeError, /CRACKER_PATH .* set ACTION to 'john' or 'hashcat'/)
    end

    it 'falls back to PATH discovery when CRACKER_PATH is unset' do
      helper.datastore['CRACKER_PATH'] = nil
      cracker = Metasploit::Framework::PasswordCracker::Cracker.new

      allow(cracker).to receive(:binary_path) do
        if cracker.cracker == 'john'
          raise Metasploit::Framework::PasswordCracker::PasswordCrackerNotFoundError
        end
        '/usr/bin/hashcat'
      end

      expect(helper.resolve_cracking_application('auto', cracker)).to eq('hashcat')
    end
  end
end
