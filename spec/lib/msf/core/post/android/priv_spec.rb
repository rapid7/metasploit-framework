# -*- coding: binary -*-

require 'msf/core/post/android/priv'

RSpec.describe Msf::Post::Android::Priv do

  subject do
    mod = Module.new
    mod.extend(described_class)
    mod
  end

  let(:nonroot_id) do
    %Q|uid=10043(u0_a43) gid=10043(u0_a43) groups=1006(camera),1015(sdcard_rw),1028(sdcard_r),3003(inet)|
  end

  let(:root_id) do
    %Q|uid=0(0)|
  end

  describe '#is_root?' do
    context 'when not root' do
      it 'returns FalseClass' do
        allow(subject).to receive(:cmd_exec).with('id').and_return(nonroot_id)
        expect(subject.is_root?).to be_falsey
      end
    end

    context 'when root' do
      it 'returns TrueClass' do
        allow(subject).to receive(:cmd_exec).with('id').and_return(root_id)
        expect(subject.is_root?).to be_truthy
      end
    end
  end

end
