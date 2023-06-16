require 'spec_helper'

RSpec.describe Msf::Auxiliary::Rocketmq do
  subject do
    mod = Msf::Module.new
    mod.extend(Msf::Auxiliary::Rocketmq)
    mod
  end

  describe 'get_rocketmq_version' do
    context 'correctly looks up id 401 as V4.9.4' do
      it 'returns that version' do
        expect(subject.get_rocketmq_version(401)).to eql('V4.9.4')
      end
    end

    context 'correctly looks up id 99999 as UNKNOWN.VERSION.ID.99999' do
      it 'returns that version' do
        expect(subject.get_rocketmq_version(99999)).to eql('UNKNOWN.VERSION.ID.99999')
      end
    end
  end
end
