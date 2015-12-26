# -*- coding: binary -*-

require 'msf/core/post/android/system'

<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
RSpec.describe Msf::Post::Android::System do
=======
describe Msf::Post::Android::System do
>>>>>>> origin/4.11.2_release_pre-rails4
=======
describe Msf::Post::Android::System do
>>>>>>> origin/chore/MSP-12110/celluloid-supervision-tree
=======
describe Msf::Post::Android::System do
>>>>>>> origin/msf-complex-payloads
=======
describe Msf::Post::Android::System do
>>>>>>> origin/msf-complex-payloads

  subject do
    mod = Module.new
    mod.extend(described_class)
    mod
  end

  let(:build_prop_output) do
    %Q|ro.build.version.sdk=16
ro.build.version.release=4.1.1
|
  end

  describe '#get_sysinfo' do
    let(:expected_android_version) do
      '4.1.1'
    end

    it 'returns the android version' do
      allow(subject).to receive(:cmd_exec).and_return(build_prop_output)
      expect(subject.get_build_prop['ro.build.version.release']).to eq(expected_android_version)
    end
  end

end
