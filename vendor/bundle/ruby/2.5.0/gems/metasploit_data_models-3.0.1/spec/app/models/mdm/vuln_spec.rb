RSpec.describe Mdm::Vuln, type: :model do
  subject(:vuln) do
    FactoryBot.build(:mdm_vuln)
  end

  it_should_behave_like 'Metasploit::Concern.run'

  context '#destroy' do
    it 'should successfully destroy the object and dependent objects' do
      vuln = FactoryBot.create(:mdm_vuln)
      vuln_attempt = FactoryBot.create(:mdm_vuln_attempt, :vuln => vuln)
      vuln_detail = FactoryBot.create(:mdm_vuln_detail, :vuln => vuln)
      vuln_ref = FactoryBot.create(:mdm_vuln_ref, :vuln => vuln)
      expect {
        vuln.destroy
      }.to_not raise_error
      expect {
        vuln.reload
      }.to raise_error(ActiveRecord::RecordNotFound)
      expect {
        vuln_attempt.reload
      }.to raise_error(ActiveRecord::RecordNotFound)
      expect {
        vuln_detail.reload
      }.to raise_error(ActiveRecord::RecordNotFound)
      expect {
        vuln_ref.reload
      }.to raise_error(ActiveRecord::RecordNotFound)
    end
  end


  context 'associations' do
    it { is_expected.to belong_to(:host).class_name('Mdm::Host') }
    it { is_expected.to belong_to(:origin) }
    it { is_expected.to belong_to(:service).class_name('Mdm::Service') }
    it { is_expected.to have_many(:module_refs).class_name('Mdm::Module::Ref').through(:refs) }
    it { is_expected.to have_many(:module_runs).class_name('MetasploitDataModels::ModuleRun') }
    it { is_expected.to have_many(:refs).class_name('Mdm::Ref').through(:vulns_refs) }
    it { is_expected.to have_many(:vuln_attempts).class_name('Mdm::VulnAttempt').dependent(:destroy) }
    it { is_expected.to have_many(:vuln_details).class_name('Mdm::VulnDetail').dependent(:destroy) }
    it { is_expected.to have_many(:vulns_refs).class_name('Mdm::VulnRef').dependent(:destroy) }
    it { is_expected.to have_many(:notes).class_name('Mdm::Note').dependent(:delete_all).order('notes.created_at') }
    it { is_expected.to have_many(:matches).class_name("MetasploitDataModels::AutomaticExploitation::Match").dependent(:destroy) }

    context 'module_details' do
      it { is_expected.to have_many(:module_details).class_name('Mdm::Module::Detail').through(:module_refs) }

      context 'with Mdm::Refs' do
        let(:names) do
          2.times.collect {
            FactoryBot.generate :mdm_ref_name
          }
        end

        let!(:refs) do
          names.collect do |name|
            FactoryBot.create(:mdm_ref, :name => name)
          end
        end

        context 'with Mdm::VulnRefs' do
          let!(:vuln_refs) do
            refs.collect { |ref|
              FactoryBot.create(:mdm_vuln_ref, :ref => ref, :vuln => vuln)
            }
          end
          
          it 'should be deletable' do
            expect {
              vuln.destroy
            }.not_to raise_error
          end
          
          context 'with Mdm::Module::Detail' do
            let!(:module_detail) do
              FactoryBot.create(
                  :mdm_module_detail
              )
            end

            context 'with Mdm::Module::Refs with same names as Mdm::Refs' do
              let!(:module_refs) do
                names.each do |name|
                  FactoryBot.create(
                      :mdm_module_ref,
                      :detail => module_detail,
                      :name => name
                  )
                end
              end

              it 'should list unique Mdm::Module::Detail' do
                expect(vuln.module_details).to match_array([module_detail])
              end

              it 'should have duplicate Mdm::Module::Details if collected through chain' do
                refs = []

                # @todo https://www.pivotaltracker.com/story/show/49004623
                vuln.vulns_refs.each do |vuln_ref|
                  refs << vuln_ref.ref
                end

                module_refs = []

                refs.each do |ref|
                  module_refs += ref.module_refs
                end

                module_details = []

                module_refs.each do |module_ref|
                  module_details << module_ref.detail
                end

                expect(vuln.module_details.count).to be < module_details.length
                expect(module_details.uniq.count).to eq(vuln.module_details.count)
              end
            end
          end
        end
      end
    end
  end

  context 'database' do
    context 'columns' do
      it { is_expected.to have_db_column(:exploited_at).of_type(:datetime) }
      it { is_expected.to have_db_column(:host_id).of_type(:integer) }
      it { is_expected.to have_db_column(:info).of_type(:string) }
      it { is_expected.to have_db_column(:name).of_type(:string) }
      it { is_expected.to have_db_column(:origin_id).of_type(:integer) }
      it { is_expected.to have_db_column(:origin_type).of_type(:string) }
      it { is_expected.to have_db_column(:service_id).of_type(:integer) }

      context 'counter caches' do
        it { is_expected.to have_db_column(:vuln_attempt_count).of_type(:integer).with_options(:default => 0) }
        it { is_expected.to have_db_column(:vuln_detail_count).of_type(:integer).with_options(:default => 0) }
      end

      context 'timestamps' do
        it { is_expected.to have_db_column(:created_at).of_type(:datetime) }
        it { is_expected.to have_db_column(:updated_at).of_type(:datetime) }
      end
    end
  end

  context 'factories' do
    context 'mdm_host_vuln' do
      subject(:mdm_host_vuln) do
        FactoryBot.build(:mdm_host_vuln)
      end

      it { is_expected.to be_valid }
    end

    context 'mdm_service_vuln' do
      subject(:mdm_service_vuln) do
        FactoryBot.build(:mdm_service_vuln)
      end

      it { is_expected.to be_valid }
    end

    context 'mdm_vuln' do
      subject(:mdm_vuln) do
        FactoryBot.build(:mdm_vuln)
      end

      it { is_expected.to be_valid }
    end
  end

  context 'scopes' do
    context 'search' do
      context 'with Mdm::Vuln' do
        subject(:results) do
          described_class.search(query)
        end

        let!(:vuln) do
          FactoryBot.create(:mdm_vuln)
        end

        context 'with Mdm::Ref' do
          let!(:ref) do
            FactoryBot.create(:mdm_ref)
          end

          context 'with Mdm::VulnRef' do
            let!(:vuln_ref) do
              FactoryBot.create(:mdm_vuln_ref, :ref => ref, :vuln => vuln)
            end

            context 'with query matching Mdm::Ref#name' do
              let(:query) do
                ref.name
              end

              it 'should match Mdm::Vuln' do
                expect(results).to match_array [vuln]
              end
            end

            context 'with query matching Mdm::Ref#name' do
              let(:query) do
                "Not #{ref.name}"
              end

              it 'should not match Mdm::Vuln' do
                expect(results).to be_empty
              end
            end
          end

          context 'without Mdm::VulnRef' do
            context 'with query matching Mdm::Vuln#name' do
              let(:query) do
                vuln.name
              end

              it 'should match Mdm::Vuln' do
                expect(results).to match_array [vuln]
              end
            end

            context 'with query not matching Mdm::Vuln#name' do
              let(:query) do
                "Not #{vuln.name}"
              end

              it 'should not match Mdm::Vuln' do
                expect(results).to be_empty
              end
            end

            context 'with query matching Mdm::Vuln#info' do
              let(:query) do
                vuln.info
              end

              it 'should match Mdm::Vuln' do
                expect(results).to match_array [vuln]
              end
            end

            context 'without query matching Mdm::Vuln#info' do
              let(:query) do
                "Not #{vuln.info}"
              end

              it 'should not match Mdm::Vuln' do
                expect(results).to be_empty
              end
            end
          end
        end

        context 'with Mdm::Host' do
          context 'with query matching Mdm::Host address' do
            let(:vuln_with_host) { FactoryBot.create(:mdm_vuln, :host)}
            let(:query) { vuln_with_host.host.address}

            it 'should match Mdm::Vuln' do
              expect(results).to match_array [vuln_with_host]
            end
          end

          context 'with query matching Mdm::Host name' do
            let(:vuln_with_host) { FactoryBot.create(:mdm_vuln, :host)}
            let(:query) { vuln_with_host.host.name}

            it 'should match Mdm::Vuln' do
              expect(results).to match_array [vuln_with_host]
            end
          end
        end
      end
    end
  end

  context 'validations' do
    it { is_expected.to validate_presence_of :name }

    context "invalid" do
      let(:mdm_vuln) do
        FactoryBot.build(:mdm_vuln)
      end

      it "should not allow :name over 255 characters" do
        str = Faker::Lorem.characters(256)
        mdm_vuln.name = str
        mdm_vuln.valid?
        expect(mdm_vuln.errors[:name][0]).to include "is too long"
      end
    end
  end
end
