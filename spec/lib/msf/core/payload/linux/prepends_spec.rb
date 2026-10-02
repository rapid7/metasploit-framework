require 'spec_helper'

RSpec.describe 'Linux payload prepends', :content do
  def prepend_object(prepends_module, enabled:)
    object = Object.new.extend(prepends_module)
    object.define_singleton_method(:datastore) do
      {
        'PayloadLinuxMinKernel' => '3.17',
        'PrependExecOnce' => enabled
      }
    end
    object.define_singleton_method(:staged?) { false }
    object
  end

  {
    x86: Msf::Payload::Linux::X86::Prepends,
    x64: Msf::Payload::Linux::X64::Prepends,
    aarch64: Msf::Payload::Linux::Aarch64::Prepends
  }.each do |architecture, prepends_module|
    context architecture do
      it 'generates every prepend and append' do
        object = prepend_object(prepends_module, enabled: false)
        generated = object.prepends_map.merge(object.appends_map)

        expect(generated).not_to be_empty
        expect(generated.values).to all(be_a(String))
        expect(generated.values).not_to include('')
      end

      it 'applies a first prepend containing a volatile marker path' do
        baseline = 'PAYLOAD'.b
        guarded = prepend_object(prepends_module, enabled: true).apply_prepends(baseline.dup)

        expect(prepend_object(prepends_module, enabled: false).apply_prepends(baseline.dup)).to eq(baseline)
        expect(prepends_module.instance_method(:prepends_order).bind(Object.new).call.first).to eq('PrependExecOnce')
        expect(guarded.bytesize).to be > baseline.bytesize
        expect(guarded).to include('/dev/shm/.msf-')
        expect(guarded).to end_with(baseline)
      end
    end
  end
end
