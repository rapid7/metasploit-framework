# frozen_string_literal: true

require 'spec_helper'

RSpec.describe 'post/windows/manage/dell_memory_protect' do
  include_context 'Msf::Simple::Framework#modules loading'

  subject(:mod) do
    load_and_create_module(
      module_type: 'post',
      reference_name: 'windows/manage/dell_memory_protect'
    )
  end

  describe 'ENABLE_MEM_PROTECT' do
    it 'defaults to the boolean false' do
      expect(mod.datastore['ENABLE_MEM_PROTECT']).to be false
    end

    it 'passes zero to the DLL when run without option validation' do
      allow(mod).to receive(:is_system?).and_return(true)
      allow(mod).to receive(:get_eproc_offsets).and_return([1, 2, 3])
      allow(mod).to receive(:sysinfo).and_return('Architecture' => ARCH_X64)
      allow(mod).to receive(:session).and_return(double(arch: ARCH_X64))
      allow(mod).to receive(:print_good)
      mod.datastore['DRIVER_PATH'] = 'C:\\dell'

      expect(mod).to receive(:execute_dll).with(
        File.join(Msf::Config.data_directory, 'exploits', 'dell_protect', 'dell_protect.x64.dll'),
        'C:\\dell,0,0,1,2,3'
      )

      mod.run
    end
  end
end
