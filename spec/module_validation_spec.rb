RSpec.describe ModuleValidation::Validator do
  let(:mod_class) { Msf::Exploit }
  let(:mod_options) do
    {
      framework: framework,
      name: 'Testing bad chars',
      author: [
        Msf::Author.new('Foobar'),
        Msf::Author.new('Jim'),
        Msf::Author.new('Bob')
      ],
      license: MSF_LICENSE,
      references: [Msf::Module::SiteReference.new('URL', 'https://example.com')],
      rank_to_s: Msf::RankingName[Msf::ExcellentRanking],
      rank: Msf::ExcellentRanking,
      notes: {
        'Stability' => [Msf::CRASH_SAFE],
        'SideEffects' => [Msf::ARTIFACTS_ON_DISK],
        'Reliability' => [Msf::FIRST_ATTEMPT_FAIL],
        'AKA' => %w[SMBGhost CoronaBlue]
      },
      stability: [Msf::CRASH_SAFE],
      side_effects: [Msf::ARTIFACTS_ON_DISK],
      reliability: [Msf::FIRST_ATTEMPT_FAIL],
      file_path: 'modules/exploits/windows/smb/cve_2020_0796_smbghost.rb',
      type: 'exploit',
      platform: Msf::Module::PlatformList.new(Msf::Module::Platform::Windows),
      targets: [Msf::Module::Target.new('Windows 10 v1903-1909 x64', { 'Platform' => 'win', 'Arch' => ['x64'] })],
      description: %q{
          A vulnerability exists within the Microsoft Server Message Block 3.1.1 (SMBv3) protocol that can be leveraged to
          execute code on a vulnerable server. This remove exploit implementation leverages this flaw to execute code
          in the context of the kernel, finally yielding a session as NT AUTHORITY\SYSTEM in spoolsv.exe. Exploitation
          can take a few minutes as the necessary data is gathered.
        }
    }
  end
  let(:framework) do
    instance_double(Msf::Framework)
  end

  let(:mod) do
    instance_double(mod_class, **mod_options)
  end

  subject { described_class.new(mod) }

  describe '#errors' do
    before(:each) do |example|
      subject.validate unless example.metadata[:skip_before]
    end

    context 'when the module is valid' do
      it 'has no errors' do
        expect(subject.errors.full_messages).to be_empty
      end
    end

    context 'when notes contains an invalid value' do
      let(:mod_options) do
        super().merge(notes: {
          'Stability' => [Msf::CRASH_SAFE],
          'SideEffects' => [Msf::ARTIFACTS_ON_DISK],
          'Reliability' => [Msf::FIRST_ATTEMPT_FAIL],
          'AKA' => %w[SMBGhost CoronaBlue],
          'NOCVE' => 'Reason not given'
        })
      end

      it 'has errors' do
        expect(subject.errors.full_messages).to eq ['Notes note value "NOCVE" must be an array, got "Reason not given"']
      end
    end

    context 'when the stability rating contains an invalid value' do
      let(:mod_options) do
        super().merge(stability: ['CRASH_SAFE'], rank: Msf::GreatRanking, rank_to_s: 'great')
      end

      it 'has errors' do
        expect(subject.errors.full_messages).to eq ['Stability contains invalid values ["CRASH_SAFE"] - only ["crash-safe", "crash-service-restarts", "crash-service-down", "crash-os-restarts", "crash-os-down", "service-resource-loss", "os-resource-loss"] is allowed']
      end
    end

    context 'when the stability rating contains an invalid values and an excellent ranking' do
      let(:mod_options) do
        super().merge(stability: [Msf::CRASH_SERVICE_RESTARTS])
      end

      it 'has errors' do
        expect(subject.errors.full_messages).to eq ['Stability must have CRASH_SAFE value if module has an ExcellentRanking, instead found ["crash-service-restarts"]']
      end
    end

    context 'when the side effects rating contains an invalid value' do
      let(:mod_options) do
        super().merge(side_effects: ['ARTIFACTS_ON_DISK'])
      end

      it 'has errors' do
        expect(subject.errors.full_messages).to eq ['Side effects contains invalid values ["ARTIFACTS_ON_DISK"] - only ["artifacts-on-disk", "config-changes", "ioc-in-logs", "account-lockouts", "account-logout", "screen-effects", "audio-effects", "physical-effects"] is allowed']
      end
    end

    context 'when the reliability rating contains an invalid value' do
      let(:mod_options) do
        super().merge(reliability: ['FIRST_ATTEMPT_FAIL'])
      end

      it 'has errors' do
        expect(subject.errors.full_messages).to eq ['Reliability contains invalid values ["FIRST_ATTEMPT_FAIL"] - only ["first-attempt-fail", "repeatable-session", "unreliable-session", "event-dependent"] is allowed']
      end
    end

    context 'when the references contains an invalid value' do
      let(:mod_options) do
        super().merge(references: [
          Msf::Module::SiteReference.new('url', 'https://example.com'),
          Msf::Module::SiteReference.new('FOO', 'https://example.com'),
          Msf::Module::SiteReference.new('NOCVE', 'Reason not given'),
          Msf::Module::SiteReference.new('AKA', 'Foobar'),
        ])
      end

      it 'has errors' do
        expect(subject.errors.full_messages).to eq [
          'References url is not valid, must be in ["CVE", "CWE", "BID", "MSB", "EDB", "US-CERT-VU", "ZDI", "URL", "WPVDB", "PACKETSTORM", "LOGO", "SOUNDTRACK", "OSVDB", "VTS", "OVE"]',
          'References FOO is not valid, must be in ["CVE", "CWE", "BID", "MSB", "EDB", "US-CERT-VU", "ZDI", "URL", "WPVDB", "PACKETSTORM", "LOGO", "SOUNDTRACK", "OSVDB", "VTS", "OVE"]',
          "References NOCVE please include NOCVE values in the 'notes' section, rather than in 'references'",
          "References AKA please include AKA values in the 'notes' section, rather than in 'references'"
        ]
      end
    end

    context 'when the license contains an invalid value' do
      let(:mod_options) do
        super().merge(license: 'MSF_LICENSE')
      end

      it 'has errors' do
        expect(subject.errors.full_messages).to eq ['License must include a valid license']
      end
    end

    context 'when the rank contains an invalid value' do
      let(:mod_options) do
        super().merge(rank: 'ExcellentRanking')
      end

      it 'has errors' do
        expect(subject.errors.full_messages).to eq ['Rank must include a valid module ranking']
      end
    end

    context 'when the author is missing' do
      let(:mod_options) do
        super().merge(author: [])
      end

      it 'has errors' do
        expect(subject.errors.full_messages).to eq ["Author can't be blank"]
      end
    end

    context 'when the author contains bad characters' do
      let(:mod_options) do
        super().merge(author: [
          Msf::Author.new('@Foobar'),
          Msf::Author.new('Foobar')
        ])
      end

      it 'has errors' do
        expect(subject.errors.full_messages).to eq ['Author must not include username handles, found "@Foobar". Try leaving it in a comment instead']
      end
    end

    context 'when the module name contains bad characters' do
      let(:mod_options) do
        super().merge(name: 'Testing <> bad & chars')
      end

      it 'has errors' do
        expect(subject.errors.full_messages).to eq ['Name must not contain the characters &<>']
      end
    end

    context 'when the module file path is not snake case' do
      let(:mod_options) do
        super().merge(file_path: 'modules/exploits/windows/smb/CVE_2020_0796_smbghost.rb')
      end

      it 'has errors' do
        expect(subject.errors.full_messages).to eq ['File path must be snake case, instead found "modules/exploits/windows/smb/CVE_2020_0796_smbghost.rb"']
      end
    end

    context 'when the description is missing' do
      let(:mod_options) do
        super().merge(description: nil)
      end

      it 'has errors' do
        expect(subject.errors.full_messages).to eq ["Description can't be blank"]
      end
    end

    context 'when the platform value is invalid', skip_before: true do
      let(:mod_options) do
        super().merge(platform: Msf::Module::PlatformList.new('foo'))
      end

      it 'raises an ArgumentError' do
        expect { subject }.to raise_error ArgumentError, 'No classes in Msf::Module::Platform for foo!'
      end
    end

    context 'when the platform is missing and targets does not contain platform values' do
      let(:mod_options) do
        super().merge(platform: nil, targets: [Msf::Module::Target.new('Windows 10 v1903-1909 x64', { 'Arch' => ['x64'] })])
      end

      it 'has errors' do
        expect(subject.errors.full_messages).to eq ['Platform must be included either within targets or platform module metadata']
      end
    end
  end
end
