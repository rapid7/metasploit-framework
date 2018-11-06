RSpec.describe Mdm::Module::Detail, type: :model do
  subject(:detail) do
    FactoryBot.build(
        :mdm_module_detail,
        :mtype => mtype,
        :stance => stance
    )
  end

  let(:mtype) do
    FactoryBot.generate :mdm_module_detail_mtype
  end

  let(:ranks) do
    [
        0,
        100,
        200,
        300,
        400,
        500,
        600
    ]
  end

  let(:stance) do
    FactoryBot.generate :mdm_module_detail_stance
  end

  let(:stances) do
    [
        'aggressive',
        'passive'
    ]
  end

  let(:types) do
    [
        'auxiliary',
        'encoder',
        'exploit',
        'nop',
        'payload',
        'post'
    ]
  end

  it_should_behave_like 'Metasploit::Concern.run'

  context 'associations' do
    it { is_expected.to have_many(:actions).class_name('Mdm::Module::Action').dependent(:destroy) }
    it { is_expected.to have_many(:archs).class_name('Mdm::Module::Arch').dependent(:destroy) }
    it { is_expected.to have_many(:authors).class_name('Mdm::Module::Author').dependent(:destroy) }
    it { is_expected.to have_many(:mixins).class_name('Mdm::Module::Mixin').dependent(:destroy) }
    it { is_expected.to have_many(:platforms).class_name('Mdm::Module::Platform').dependent(:destroy) }
    it { is_expected.to have_many(:refs).class_name('Mdm::Module::Ref').dependent(:destroy) }
    it { is_expected.to have_many(:targets).class_name('Mdm::Module::Target').dependent(:destroy) }
  end

  context 'CONSTANTS' do
    context 'DIRECTORY_BY_TYPE' do
      subject(:directory_by_type) do
        described_class::DIRECTORY_BY_TYPE
      end

      it "maps 'auxiliary' to 'auxiliary'" do
        expect(directory_by_type['auxiliary']).to eq('auxiliary')
      end

      it "maps 'encoder' to 'encoders'" do
        expect(directory_by_type['encoder']).to eq('encoders')
      end

      it "maps 'exploit' to 'exploits'" do
        expect(directory_by_type['exploit']).to eq('exploits')
      end

      it "maps 'nop' to 'nops'" do
        expect(directory_by_type['nop']).to eq('nops')
      end

      it "maps 'payload' to 'payloads'" do
        expect(directory_by_type['payload']).to eq('payloads')
      end

      it "maps 'post' to 'post'" do
        expect(directory_by_type['post']).to eq('post')
      end
    end

    context 'PRIVILEGES' do
      subject(:privileges) do
        described_class::PRIVILEGES
      end

      it 'should contain both Boolean values' do
        expect(privileges).to include(false)
        expect(privileges).to include(true)
      end
    end

    context 'RANK_BY_NAME' do
      subject(:rank_by_name) do
        described_class::RANK_BY_NAME
      end

      it "maps 'Manual' to 0" do
        expect(rank_by_name['Manual']).to eq(0)
      end

      it "maps 'Low' to 100" do
        expect(rank_by_name['Low']).to eq(100)
      end

      it "maps 'Average' to 200" do
        expect(rank_by_name['Average']).to eq(200)
      end

      it "maps 'Normal' to 300" do
        expect(rank_by_name['Normal']).to eq(300)
      end

      it "maps 'Good' to 400" do
        expect(rank_by_name['Good']).to eq(400)
      end

      it "maps 'Great' to 500" do
        expect(rank_by_name['Great']).to eq(500)
      end

      it "maps 'Excellent' to 600" do
        expect(rank_by_name['Excellent']).to eq(600)
      end
    end

    context 'STANCES' do
      subject(:stances) do
        described_class::STANCES
      end

      it { is_expected.to include('aggressive') }
      it { is_expected.to include('passive') }
    end
  end

  context 'database' do
    context 'columns' do
      it { is_expected.to have_db_column(:default_target).of_type(:integer) }
      it { is_expected.to have_db_column(:description).of_type(:text) }
      it { is_expected.to have_db_column(:disclosure_date).of_type(:datetime)}
      it { is_expected.to have_db_column(:file).of_type(:text) }
      it { is_expected.to have_db_column(:fullname).of_type(:text) }
      it { is_expected.to have_db_column(:license).of_type(:string) }
      it { is_expected.to have_db_column(:mtime).of_type(:datetime) }
      it { is_expected.to have_db_column(:mtype).of_type(:string) }
      it { is_expected.to have_db_column(:name).of_type(:text) }
      it { is_expected.to have_db_column(:privileged).of_type(:boolean) }
      it { is_expected.to have_db_column(:rank).of_type(:integer) }
      it { is_expected.to have_db_column(:ready).of_type(:boolean) }
      it { is_expected.to have_db_column(:refname).of_type(:text) }
      it { is_expected.to have_db_column(:stance).of_type(:string).with_options(:null => true) }
    end

    context 'indices' do
      it { is_expected.to have_db_index(:description) }
      it { is_expected.to have_db_index(:mtype) }
      it { is_expected.to have_db_index(:name) }
      it { is_expected.to have_db_index(:refname) }
    end
  end

  context 'factories' do
    context 'mdm_module_detail' do
      subject(:mdm_module_detail) do
        FactoryBot.build(:mdm_module_detail)
      end

      it { is_expected.to be_valid }

      context 'stance' do
        subject(:mdm_module_detail) do
          FactoryBot.build(:mdm_module_detail, :mtype => mtype)
        end

        context 'with supports_stance?' do
          let(:mtype) do
            'exploit'
          end

          it { is_expected.to be_valid }

          context '#stance' do
            subject(:stance) {
              mdm_module_detail.stance
            }

            it { is_expected.not_to be_nil }
          end

          context '#supports_stance?' do
            subject(:supports_stance?) {
              mdm_module_detail.supports_stance?
            }

            it { is_expected.to eq(true) }
          end
        end

        context 'without supports_stance?' do
          let(:mtype) do
            'post'
          end

          it { is_expected.to be_valid }

          context '#stance' do
            subject(:stance) {
              mdm_module_detail.stance
            }

            it { is_expected.to be_nil }
          end

          context '#supports_stance?' do
            subject(:supports_stance?) {
              mdm_module_detail.supports_stance?
            }

            it { is_expected.to eq(false) }
          end
        end
      end
    end
  end

  context 'scopes' do

    before(:each) do
      @ms12_020 = FactoryBot.create(:mdm_module_detail,
        name: "MS12-020 Microsoft Remote Desktop Use-After-Free DoS",
        fullname: 'auxiliary/dos/windows/rdp/ms12_020_maxchannelids',
        description: "This module exploits the MS12-020 RDP vulnerability originally discovered and\n        reported by Luigi Auriemma.  The flaw can be found in the way the T.125\n        ConnectMCSPDU packet is handled in the maxChannelIDs field, which will result\n        an invalid pointer being used, therefore causing a denial-of-service condition.",
        mtype: 'auxiliary',
        stance: 'aggressive')
      @ms08_067 = FactoryBot.create(:mdm_module_detail,
        name: "MS08-067 Microsoft Server Service Relative Path Stack Corruption",
        fullname: 'exploit/windows/smb/ms08_067_netapi',
        description: "This module exploits a parsing flaw in the path canonicalization code of\n        NetAPI32.dll through the Server Service. This module is capable of bypassing\n        NX on some operating systems and service packs. The correct target must be\n        used to prevent the Server Service (along with a dozen others in the same\n        process) from crashing. Windows XP targets seem to handle multiple successful\n        exploitation events, but 2003 targets will often crash or hang on subsequent\n        attempts. This is just the first version of this module, full support for\n        NX bypass on 2003, along with other platforms, is still in development.",
        mtype: 'exploit',
        stance: 'aggressive')
      @ms06_040 = FactoryBot.create(:mdm_module_detail,
        name: "MS06-040 Microsoft Server Service NetpwPathCanonicalize Overflow",
        fullname: 'exploit/windows/smb/ms06_040_netapi',
        description: "This module exploits a stack buffer overflow in the NetApi32 CanonicalizePathName() function\n        using the NetpwPathCanonicalize RPC call in the Server Service. It is likely that\n        other RPC calls could be used to exploit this service. This exploit will result in\n        a denial of service on Windows XP SP2 or Windows 2003 SP1. A failed exploit attempt\n        will likely result in a complete reboot on Windows 2000 and the termination of all\n        SMB-related services on Windows XP. The default target for this exploit should succeed\n        on Windows NT 4.0, Windows 2000 SP0-SP4+, Windows XP SP0-SP1 and Windows 2003 SP0.",
        mtype: 'exploit',
        stance: 'aggressive')
      @cve_2012_0507 = FactoryBot.create(:mdm_module_detail,
        name: "Java AtomicReferenceArray Type Violation Vulnerability",
        fullname: 'exploit/multi/browser/java_atomicreferencearray',
        description: "This module exploits a vulnerability due to the fact that\n        AtomicReferenceArray uses the Unsafe class to store a reference in an\n        array directly, which may violate type safety if not used properly.\n        This allows a way to escape the JRE sandbox, and load additional classes\n        in order to perform malicious operations.",
        mtype: 'exploit',
        stance: 'passive')
      @cve_2010_0425 = FactoryBot.create(:mdm_module_detail,
        name: "PHP Remote File Include Generic Code Execution",
        fullname: 'exploit/unix/webapp/php_include',
        description: "This module can be used to exploit any generic PHP file include vulnerability,\n        where the application includes code like the following:\n\n        <?php include($_GET['path']); ?>",
        mtype: 'exploit',
        stance: 'aggressive')

      @author1 = "hdm <x@hdm.io>"
      @author2 = "jduck <jduck@metasploit.com>"
      @author3 = "juan vazquez <juan.vazquez@metasploit.com>"
      @author4 = "egypt <egypt@metasploit.com>"

      FactoryBot.create(:mdm_module_author, detail: @ms12_020, name: @author2)
      FactoryBot.create(:mdm_module_author, detail: @ms08_067, name: @author1)
      FactoryBot.create(:mdm_module_author, detail: @ms08_067, name: @author2)
      FactoryBot.create(:mdm_module_author, detail: @ms06_040, name: @author1)
      FactoryBot.create(:mdm_module_author, detail: @cve_2012_0507, name: @author3)
      FactoryBot.create(:mdm_module_author, detail: @cve_2012_0507, name: @author4)

      FactoryBot.create(:mdm_module_platform, detail: @ms12_020, name: 'windows')
      FactoryBot.create(:mdm_module_platform, detail: @ms08_067, name: 'windows')
      FactoryBot.create(:mdm_module_platform, detail: @ms06_040, name: 'windows')
      FactoryBot.create(:mdm_module_platform, detail: @cve_2012_0507, name: 'linux')
      FactoryBot.create(:mdm_module_platform, detail: @cve_2012_0507, name: 'java')

      FactoryBot.create(:mdm_module_arch, detail: @cve_2012_0507, name: '["ppc"]')
      FactoryBot.create(:mdm_module_arch, detail: @cve_2012_0507, name: '["x86"]')
      FactoryBot.create(:mdm_module_arch, detail: @cve_2012_0507, name: '["java"]')
      FactoryBot.create(:mdm_module_arch, detail: @cve_2010_0425, name: 'php')

      FactoryBot.create(:mdm_module_ref, detail: @ms12_020, name: 'EDB-18606')
      FactoryBot.create(:mdm_module_ref, detail: @ms12_020, name: 'MSB-MS12-020')
      FactoryBot.create(:mdm_module_ref, detail: @ms12_020, name: 'CVE-2012-0002')
      FactoryBot.create(:mdm_module_ref, detail: @ms08_067, name: 'MSB-MS08-067')
      FactoryBot.create(:mdm_module_ref, detail: @ms08_067, name: 'OSVDB-49243')
      FactoryBot.create(:mdm_module_ref, detail: @ms08_067, name: 'CVE-2008-4250')
      FactoryBot.create(:mdm_module_ref, detail: @ms06_040, name: 'MSB-MS06-040')
      FactoryBot.create(:mdm_module_ref, detail: @ms06_040, name: 'BID-19409')
      FactoryBot.create(:mdm_module_ref, detail: @ms06_040, name: 'OSVDB-27845')
      FactoryBot.create(:mdm_module_ref, detail: @ms06_040, name: 'CVE-2006-3439')
      FactoryBot.create(:mdm_module_ref, detail: @cve_2012_0507, name: 'BID-52161')
      FactoryBot.create(:mdm_module_ref, detail: @cve_2012_0507, name: 'OSVDB-80724')
      FactoryBot.create(:mdm_module_ref, detail: @cve_2012_0507, name: 'CVE-2012-0507')

      FactoryBot.create(:mdm_module_target, detail: @ms08_067, name: 'Windows 2003 SP2 English (NX)')
      FactoryBot.create(:mdm_module_target, detail: @ms08_067, name: 'Windows 2003 SP2 English (NO NX)')
      FactoryBot.create(:mdm_module_target, detail: @ms08_067, name: 'Windows 2003 SP1 English (NX)')
      FactoryBot.create(:mdm_module_target, detail: @ms08_067, name: 'Windows 2003 SP1 English (NO NX)')
      FactoryBot.create(:mdm_module_target, detail: @ms08_067, name: 'Windows XP SP3 English (NX)')
      FactoryBot.create(:mdm_module_target, detail: @ms08_067, name: 'Windows XP SP3 English (AlwaysOn NX)')
      FactoryBot.create(:mdm_module_target, detail: @ms08_067, name: 'Windows XP SP2 English (NX)')
      FactoryBot.create(:mdm_module_target, detail: @ms08_067, name: 'Windows XP SP2 English (AlwaysOn NX)')
      FactoryBot.create(:mdm_module_target, detail: @ms08_067, name: 'Automatic Targeting')
      FactoryBot.create(:mdm_module_target, detail: @ms06_040, name: '(wcscpy) Windows 2003 SP0')
      FactoryBot.create(:mdm_module_target, detail: @ms06_040, name: '(stack)  Windows XP SP1 English')
      FactoryBot.create(:mdm_module_target, detail: @ms06_040, name: '(wcscpy) Windows XP SP0/SP1')
      FactoryBot.create(:mdm_module_target, detail: @ms06_040, name: '(wcscpy) Windows NT 4.0 / Windows 2000 SP0-SP4')
      FactoryBot.create(:mdm_module_target, detail: @ms06_040, name: '(wcscpy) Automatic (NT 4.0, 2000 SP0-SP4, XP SP0-SP1)')
      FactoryBot.create(:mdm_module_target, detail: @cve_2012_0507, name: 'Linux x86 (Native Payload)')
      FactoryBot.create(:mdm_module_target, detail: @cve_2012_0507, name: 'Mac OS X x86 (Native Payload)')
      FactoryBot.create(:mdm_module_target, detail: @cve_2012_0507, name: 'Mac OS X PPC (Native Payload)')
      FactoryBot.create(:mdm_module_target, detail: @cve_2012_0507, name: 'Windows x86 (Native Payload)')
      FactoryBot.create(:mdm_module_target, detail: @cve_2012_0507, name: 'Generic (Java Payload)')
      FactoryBot.create(:mdm_module_target, detail: @cve_2010_0425, name: 'Automatic')
    end

    context '#module_arch' do
      it 'finds all modules with a stance matching "java"' do
        expect(Mdm::Module::Detail.module_arch(['%java%']).uniq).to contain_exactly(@cve_2012_0507)
      end
      it 'finds all modules with a stance matching "pass"' do
        expect(Mdm::Module::Detail.module_arch(['%java%', '%php%']).uniq).to contain_exactly(@cve_2012_0507, @cve_2010_0425)
      end
    end

    context '#module_author' do
      it 'finds all modules with author matching "Juan"' do
        expect(Mdm::Module::Detail.module_author(['%juan%'])).to contain_exactly(@cve_2012_0507)
      end

      it 'finds all modules for author matching "hdm"' do
        expect(Mdm::Module::Detail.module_author(['%hdm%'])).to contain_exactly(@ms08_067, @ms06_040)
      end
      it 'finds all modules with authors matching "juan", "jduck"' do
        expect(Mdm::Module::Detail.module_author(['%juan%','%jduck%'])).to contain_exactly(@ms12_020,@ms08_067,@cve_2012_0507)
      end
    end

    context '#module_name' do
      it 'finds all modules with name matching "DoS"' do
        expect(Mdm::Module::Detail.module_name(['%DoS%'])).to contain_exactly(@ms12_020)
      end

      it 'finds all modules with name matching "netapi"' do
        expect(Mdm::Module::Detail.module_name(['%netapi%'])).to contain_exactly(@ms08_067, @ms06_040)
      end

      it 'finds all modules with name matching "browser"' do
        expect(Mdm::Module::Detail.module_name(['%browser%'])).to contain_exactly(@cve_2012_0507)
      end
    end

    context '#module_os_or_platform' do
      it 'finds all modules with a platform matching "linux"' do
        expect(Mdm::Module::Detail.module_os_or_platform(['%linux%']).uniq).to contain_exactly(@cve_2012_0507)
      end

      it 'finds all modules with a platform matching "windows"' do
        expect(Mdm::Module::Detail.module_os_or_platform(['%windows%']).uniq).to contain_exactly(
          @ms12_020,@ms08_067,@ms06_040,@cve_2012_0507)
      end
    end

    context 'module_ref' do
      it 'finds all modules with a reff matching "CVE-2012"' do
        expect(Mdm::Module::Detail.module_ref(['%CVE-2012%']).uniq).to contain_exactly(
          @ms12_020,@cve_2012_0507)
      end
      it 'finds all modules with a reff matching "EDB"' do
        expect(Mdm::Module::Detail.module_ref(['%EDB%']).uniq).to contain_exactly(@ms12_020)
      end
    end

    context '#module_stance' do
      it 'finds all modules with a stance matching "agg"' do
        expect(Mdm::Module::Detail.module_stance(['%agg%']).uniq).to contain_exactly(
          @ms12_020,@ms08_067,@ms06_040,@cve_2010_0425)
      end
      it 'finds all modules with a stance matching "pass"' do
        expect(Mdm::Module::Detail.module_stance(['%pass%']).uniq).to contain_exactly(@cve_2012_0507)
      end
    end

    context '#module_text' do
      it 'finds all modules with a description matching "ConnectMCSPDU"' do
        expect(Mdm::Module::Detail.module_text(['%ConnectMCSPDU%']).uniq).to contain_exactly(@ms12_020)
      end
      it 'finds all modules with a fullname matching "smb/ms0"' do
        expect(Mdm::Module::Detail.module_text(['%smb/ms0%']).uniq).to contain_exactly(@ms08_067,@ms06_040)
      end
      it 'finds all modules with a name matching "Microsoft Server Service"' do
        expect(Mdm::Module::Detail.module_text(['%Microsoft Server Service%']).uniq).to contain_exactly(@ms08_067,@ms06_040)
      end
      it 'finds all modules with a arch matching "php"' do
        expect(Mdm::Module::Detail.module_text(['%php%']).uniq).to contain_exactly(@cve_2010_0425)
      end
      it 'finds all modules with a author matching "jduck"' do
        expect(Mdm::Module::Detail.module_text(['%jduck%']).uniq).to contain_exactly(@ms12_020,@ms08_067)
      end
      it 'finds all modules with a platform matching "linux"' do
        expect(Mdm::Module::Detail.module_text(['%linux%']).uniq).to contain_exactly(@cve_2012_0507)
      end
      it 'finds all modules with a ref matching "MSB-MS"' do
        expect(Mdm::Module::Detail.module_text(['%MSB-MS%']).uniq).to contain_exactly(@ms12_020,@ms08_067,@ms06_040)
      end
      it 'finds all modules with a target matching "Auto"' do
        expect(Mdm::Module::Detail.module_text(['%Auto%']).uniq).to contain_exactly(@ms08_067,@ms06_040,@cve_2010_0425)
      end
    end

    context 'module_type' do
      it 'finds all modules with a mtype matching "aux"' do
        expect(Mdm::Module::Detail.module_type(['%aux%']).uniq).to contain_exactly(@ms12_020)
      end
      it 'finds all modules with a mtype matching "exp"' do
        expect(Mdm::Module::Detail.module_type(['%exp%']).uniq).to contain_exactly(
          @ms08_067,@ms06_040,@cve_2012_0507,@cve_2010_0425)
      end
    end


  end

  context 'validations' do
    it { is_expected.to validate_inclusion_of(:mtype).in_array(types) }

    # Because the boolean field will cast most strings to false,
    # validate_inclusion_of(:privileged).in_array([true, false]) will fail on the disallowed values check.

    context 'rank' do
      it 'validates rank is only an integer' do
        is_expected.to validate_numericality_of(:rank).only_integer
      end

      it { is_expected.to validate_inclusion_of(:rank).in_array(ranks) }
    end

    it { is_expected.to validate_presence_of(:refname) }

    context 'stance' do
      context 'mtype' do
        it_should_behave_like 'Mdm::Module::Detail supports stance with mtype', 'auxiliary'
        it_should_behave_like 'Mdm::Module::Detail supports stance with mtype', 'exploit'

        it_should_behave_like 'Mdm::Module::Detail does not support stance with mtype', 'encoder'
        it_should_behave_like 'Mdm::Module::Detail does not support stance with mtype', 'nop'
        it_should_behave_like 'Mdm::Module::Detail does not support stance with mtype', 'payload'
        it_should_behave_like 'Mdm::Module::Detail does not support stance with mtype', 'post'
      end
    end
  end

  context 'with saved' do
    before(:example) do
      detail.save!
    end

    context '#add_action' do
      def add_action
        detail.add_action(name)
      end

      let(:name) do
        FactoryBot.generate :mdm_module_action_name
      end

      it 'should add an Mdm::Action under the Mdm::ModuleDetail' do
        expect {
          add_action
        }.to change(detail.actions, :length).by(1)
      end

      context 'new Mdm::Action' do
        subject(:module_action) do
          add_action

          detail.actions.last
        end

        it { is_expected.to be_valid }

        context '#name' do
          it 'is name passed to add_action' do
            expect(module_action.name).to eq(name)
          end
        end
      end
    end

    context '#add_arch' do
      def add_arch
        detail.add_arch(name)
      end

      let(:name) do
        FactoryBot.generate :mdm_module_arch_name
      end

      it 'should add an Mdm::ModuleArch under the Mdm::ModuleDetail' do
        expect {
          add_arch
        }.to change(detail.archs, :length).by(1)
      end

      context 'new Mdm::ModuleArch' do
        subject(:module_arch) do
          add_arch

          detail.archs.last
        end

        it { is_expected.to be_valid }

        context '#name' do
          it 'is name passed to add_arch' do
            expect(module_arch.name).to eq(name)
          end
        end
      end
    end

    context '#add_author' do
      let(:name) do
        FactoryBot.generate :mdm_module_author_name
      end

      context 'with email' do
        def add_author
          detail.add_author(name, email)
        end

        let(:email) do
          FactoryBot.generate :mdm_module_author_email
        end

        it 'should add an Mdm::ModuleAuthor under the Mdm::ModuleDetail' do
          expect {
            add_author
          }.to change(detail.authors, :length).by(1)
        end

        context 'new Mdm::ModuleAuthor' do
          subject(:module_author) do
            add_author

            detail.authors.last
          end

          it { is_expected.to be_valid }

          context '#email' do
            it 'is email passed to add_author' do
              expect(module_author.email).to eq(email)
            end
          end

          context '#name' do
            it 'is name passed to add_author' do
              expect(module_author.name).to eq(name)
            end
          end
        end
      end

      context 'without email' do
        def add_author
          detail.add_author(name)
        end

        it 'should add an Mdm::ModuleAuthor under the Mdm::ModuleDetail' do
          expect {
            add_author
          }.to change(detail.authors, :length).by(1)
        end

        context 'new Mdm::ModuleAuthor' do
          subject(:module_author) do
            add_author

            detail.authors.last
          end

          it { is_expected.to be_valid }

          context '#email' do
            subject(:module_author_email) {
              module_author.email
            }

            it { is_expected.to be_nil }
          end

          context '#name' do
            it 'is name passed to add_author' do
              expect(module_author.name).to eq(name)
            end
          end
        end
      end
    end

    context '#add_mixin' do
      def add_mixin
        detail.add_mixin(name)
      end

      let(:name) do
        FactoryBot.generate :mdm_module_mixin_name
      end

      it 'should add an Mdm::ModuleMixin under the Mdm::ModuleDetail' do
        expect {
          add_mixin
        }.to change(detail.mixins, :length).by(1)
      end

      context 'new Mdm::ModuleMixin' do
        subject(:mdm_module_mixin) do
          add_mixin

          detail.mixins.last
        end

        it { is_expected.to be_valid }

        context '#name' do
          it 'is name passed to add_mixin' do
            expect(mdm_module_mixin.name).to eq(name)
          end
        end
      end
    end

    context '#add_platform' do
      def add_platform
        detail.add_platform(name)
      end

      let(:name) do
        FactoryBot.generate :mdm_module_platform_name
      end

      it 'should add an Mdm::ModulePlatform under the Mdm::ModuleDetail' do
        expect {
          add_platform
        }.to change(detail.platforms, :length).by(1)
      end

      context 'new Mdm::ModulePlatform' do
        subject(:module_platform) do
          add_platform

          detail.platforms.last
        end

        it { is_expected.to be_valid }

        context '#name' do
          it 'is name passed to add_platform' do
            expect(module_platform.name).to eq(name)
          end
        end
      end
    end

    context '#add_ref' do
      def add_ref
        detail.add_ref(name)
      end

      let(:name) do
        FactoryBot.generate :mdm_module_ref_name
      end

      it 'should add an Mdm::ModuleRef under the Mdm::ModuleDetail' do
        expect {
          add_ref
        }.to change(detail.refs, :length).by(1)
      end

      context 'new Mdm::ModuleRef' do
        subject(:module_ref) do
          add_ref

          detail.refs.last
        end

        it { is_expected.to be_valid }

        context '#name' do
          it 'is name passed to add_ref' do
            expect(module_ref.name).to eq(name)
          end
        end
      end
    end

    context '#add_target' do
      def add_target
        detail.add_target(index, name)
      end

      let(:index) do
        FactoryBot.generate :mdm_module_target_index
      end

      let(:name) do
        FactoryBot.generate :mdm_module_target_name
      end

      it 'should add an Mdm::ModuleTarget under the Mdm::ModuleDetail' do
        expect {
          add_target
        }.to change(detail.targets, :length).by(1)
      end

      context 'new Mdm::ModuleTarget' do
        subject(:module_target) do
          add_target

          detail.targets.last
        end

        it { is_expected.to be_valid }

        context '#name' do
          it 'is name passed to add_target' do
            expect(module_target.name).to eq(name)
          end
        end
      end
    end
  end
end
