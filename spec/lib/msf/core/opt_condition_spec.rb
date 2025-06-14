# -*- coding:binary -*-

require 'spec_helper'

RSpec.describe Msf::OptCondition do
  describe '.format_conditions' do
    [
      {
        conditions: ['Winrm::Auth', '==', 'kerberos'],
        expected: 'Winrm::Auth is kerberos'
      },
      {
        conditions: %w[TARGET != Automatic],
        expected: 'TARGET is not Automatic'
      },
      {
        conditions: ['ACTION', 'in', %w[VSS_MOUNT VSS_UNMOUNT]],
        expected: 'ACTION is one of VSS_MOUNT,VSS_UNMOUNT'
      },
      {
        conditions: ['Winrm::Auth', 'nin', ['kerberos', 'plain']],
        expected: 'Winrm::Auth not in kerberos,plain'
      },
      {
        conditions: ['ScheduleRemoteSystem', 'in', [nil, '']],
        expected: 'ScheduleRemoteSystem is blank'
      },
      {
        conditions: ['ScheduleRemoteSystem', 'nin', [nil, '']],
        expected: 'ScheduleRemoteSystem is not blank'
      },
    ].each do |test|
      context "when the conditions are #{test[:conditions].inspect}" do
        it "returns the expected string #{test[:expected]}" do
          mod = instance_double(Msf::Module)
          option = Msf::OptString.new('foo', conditions: test[:conditions])
          expect(described_class.format_conditions(mod, option)).to eq test[:expected]
        end
      end
    end
  end
end
