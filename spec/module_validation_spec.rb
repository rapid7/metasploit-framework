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
      arch: [Rex::Arch::ARCH_X86],
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
          Msf::Module::SiteReference.new('ATTACK', 'Foobar'),
        ])
      end

      it 'has errors' do
        expect(subject.errors.full_messages).to eq [
          "References url is not valid, must be in [\"ATT&CK\", \"CVE\", \"CWE\", \"BID\", \"MSB\", \"EDB\", \"US-CERT-VU\", \"ZDI\", \"URL\", \"WPVDB\", \"PACKETSTORM\", \"LOGO\", \"SOUNDTRACK\", \"OSVDB\", \"VTS\", \"OVE\"]",
          "References FOO is not valid, must be in [\"ATT&CK\", \"CVE\", \"CWE\", \"BID\", \"MSB\", \"EDB\", \"US-CERT-VU\", \"ZDI\", \"URL\", \"WPVDB\", \"PACKETSTORM\", \"LOGO\", \"SOUNDTRACK\", \"OSVDB\", \"VTS\", \"OVE\"]",
          "References NOCVE please include NOCVE values in the 'notes' section, rather than in 'references'",
          "References AKA please include AKA values in the 'notes' section, rather than in 'references'",
          "References ATTACK is not valid, must be in [\"ATT&CK\", \"CVE\", \"CWE\", \"BID\", \"MSB\", \"EDB\", \"US-CERT-VU\", \"ZDI\", \"URL\", \"WPVDB\", \"PACKETSTORM\", \"LOGO\", \"SOUNDTRACK\", \"OSVDB\", \"VTS\", \"OVE\"]"
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

    context 'when the name has non-printable ascii characters' do
      let(:mod_options) do
        super().merge(name: 'Testing human-readable printable ascii characters ≤')
      end

      it 'has errors' do
        expect(subject.errors.full_messages).to eq ['Name must only contain human-readable printable ascii characters']
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

    context 'when the description has non-printable ascii characters' do
      let(:mod_options) do
        super().merge(description: "Testing human-readable printable ascii characters ≤\n\tand newlines/tabs")
      end

      it 'has errors' do
        expect(subject.errors.full_messages).to eq ['Description must only contain human-readable printable ascii characters, including newlines and tabs']
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

    context 'when the arch array contains a valid value' do
      it 'has no errors' do
        expect(subject.errors.full_messages).to be_empty
      end
    end

    context 'when the arch array contains an invalid value' do
      let(:mod_options) do
        super().merge(arch: ["Rex::Arch::ARCH_X86"])
      end

      it 'has errors' do
        expect(subject.errors.full_messages).to eq ["Arch contains invalid values [\"Rex::Arch::ARCH_X86\"] - only [\"x86\", \"x86_64\", \"x64\", \"mips\", \"mipsle\", \"mipsbe\", \"mips64\", \"mips64le\", \"ppc\", \"ppce500v2\", \"ppc64\", \"ppc64le\", \"cbea\", \"cbea64\", \"sparc\", \"sparc64\", \"armle\", \"armbe\", \"aarch64\", \"cmd\", \"php\", \"tty\", \"java\", \"ruby\", \"dalvik\", \"python\", \"nodejs\", \"firefox\", \"zarch\", \"r\", \"riscv32be\", \"riscv32le\", \"riscv64be\", \"riscv64le\", \"loongarch64\"] is allowed"]
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

    context 'when the notes section contains sentinel values' do
      let(:mod_options) do
        new_module_options = {
          notes: {
            'Stability' => Msf::UNKNOWN_STABILITY,
            'SideEffects' => Msf::UNKNOWN_SIDE_EFFECTS,
            'Reliability' => Msf::UNKNOWN_RELIABILITY,
          },
          stability: Msf::UNKNOWN_STABILITY,
          side_effects: Msf::UNKNOWN_SIDE_EFFECTS,
          reliability: Msf::UNKNOWN_RELIABILITY,
        }
        super().merge(new_module_options)
      end

      it 'has no errors' do
        expect(subject.errors.full_messages).to be_empty
      end
    end

    context 'when the notes section contains in correct sentinel values' do
      let(:mod_options) do
        new_module_options = {
          notes: {
            'Stability' => [Msf::UNKNOWN_STABILITY],
            'SideEffects' => [Msf::UNKNOWN_SIDE_EFFECTS],
            'Reliability' => [Msf::UNKNOWN_RELIABILITY],
          },
          stability: [Msf::UNKNOWN_STABILITY],
          side_effects: [Msf::UNKNOWN_SIDE_EFFECTS],
          reliability: [Msf::UNKNOWN_RELIABILITY],
        }
        super().merge(new_module_options, rank: Msf::GreatRanking, rank_to_s: 'great')
      end

      it 'has errors' do
        expect(subject.errors.full_messages).to eq [
          "Stability contains invalid values [[\"unknown-stability\"]] - only [\"crash-safe\", \"crash-service-restarts\", \"crash-service-down\", \"crash-os-restarts\", \"crash-os-down\", \"service-resource-loss\", \"os-resource-loss\"] is allowed",
          "Side effects contains invalid values [[\"unknown-side-effects\"]] - only [\"artifacts-on-disk\", \"config-changes\", \"ioc-in-logs\", \"account-lockouts\", \"account-logout\", \"screen-effects\", \"audio-effects\", \"physical-effects\"] is allowed",
          "Reliability contains invalid values [[\"unknown-reliability\"]] - only [\"first-attempt-fail\", \"repeatable-session\", \"unreliable-session\", \"event-dependent\"] is allowed"
        ]
      end
    end


    context 'when the references contains ATT&CK values' do
      let(:mod_options) do
        super().merge(references: [
          Msf::Module::SiteReference.new('ATT&CK', 'T1059.001'),
          Msf::Module::SiteReference.new('ATT&CK', 'BAD1059.001')
        ])
      end

      it 'has errors for invalid ATT&CK references' do
        expect(subject.errors.full_messages).to eq ["References ATT&CK reference 'BAD1059.001' is invalid. Must start with one of [\"TA\", \"DS\", \"S\", \"M\", \"A\", \"G\", \"C\", \"T\"] and be followed by digits/periods, no whitespace."]
      end

      context 'with only valid ATT&CK references' do
        let(:mod_options) do
          super().merge(references: [Msf::Module::SiteReference.new('ATT&CK', 'T1059.001')])
        end

        it 'has no errors' do
          expect(subject.errors.full_messages).to be_empty
        end
      end
    end
  end
end
