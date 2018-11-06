RSpec.describe Mdm::Workspace, type: :model do
  subject(:workspace) do
    FactoryBot.build(:mdm_workspace)
  end

  let(:default) do
    'default'
  end

  it_should_behave_like 'Metasploit::Concern.run'

  context 'factory' do
    it 'should be valid' do
      workspace = FactoryBot.build(:mdm_workspace)
      expect(workspace).to be_valid
    end
  end

  context '#destroy' do
    it 'should successfully destroy the object and dependent objects' do
      workspace = FactoryBot.create(:mdm_workspace)
      listener = FactoryBot.create(:mdm_listener, :workspace => workspace)
      task = FactoryBot.create(:mdm_task, :workspace => workspace)

      expect {
        workspace.destroy
      }.to_not raise_error
      expect {
        workspace.reload
      }.to raise_error(ActiveRecord::RecordNotFound)
      expect {
        listener.reload
      }.to raise_error(ActiveRecord::RecordNotFound)
      expect {
        task.reload
      }.to raise_error(ActiveRecord::RecordNotFound)
    end
  end

  context 'associations' do
    it { is_expected.to have_many(:clients).class_name('Mdm::Client').through(:hosts) }
    it { is_expected.to have_many(:creds).class_name('Mdm::Cred').through(:services) }
    it { is_expected.to have_many(:events).class_name('Mdm::Event') }
    it { is_expected.to have_many(:exploited_hosts).class_name('Mdm::ExploitedHost').through(:hosts) }
    it { is_expected.to have_many(:hosts).class_name('Mdm::Host') }
    it { is_expected.to have_many(:listeners).class_name('Mdm::Listener').dependent(:destroy) }
    it { is_expected.to have_many(:loots).class_name('Mdm::Loot').through(:hosts) }
    it { is_expected.to have_many(:notes).class_name('Mdm::Note') }
    it { is_expected.to belong_to(:owner).class_name('Mdm::User').with_foreign_key('owner_id') }
    it { is_expected.to have_many(:services).class_name('Mdm::Service').through(:hosts).with_foreign_key('service_id') }
    it { is_expected.to have_many(:sessions).class_name('Mdm::Session').through(:hosts) }
    it { is_expected.to have_many(:tasks).class_name('Mdm::Task').dependent(:destroy).order('created_at DESC') }
    it { is_expected.to have_and_belong_to_many(:users).class_name('Mdm::User') }
    it { is_expected.to have_many(:vulns).class_name('Mdm::Vuln').through(:hosts) }
  end

  context 'callbacks' do
    context 'before_save' do
      context '#normalize' do
        it 'should be called' do
          expect(workspace).to receive(:normalize)
          workspace.run_callbacks(:save)
        end
      end
    end
  end

  context 'columns' do
    it { is_expected.to have_db_column(:boundary).of_type(:string).with_options(:limit => 4 * (2 ** 10)) }
    it { is_expected.to have_db_column(:description).of_type(:string).with_options(:limit => 4 * (2 ** 10)) }
    it { is_expected.to have_db_column(:limit_to_network).of_type(:boolean).with_options(:default => false, :null => false) }
    it { is_expected.to have_db_column(:name).of_type(:string) }
    it { is_expected.to have_db_column(:owner_id).of_type(:integer) }

    context 'timestamps' do
      it { is_expected.to have_db_column(:created_at).of_type(:datetime).with_options(:null => false) }
      it { is_expected.to have_db_column(:updated_at).of_type(:datetime).with_options(:null => false) }
    end
  end

  context 'CONSTANTS' do
    it 'should define the DEFAULT name' do
      expect(described_class::DEFAULT).to eq(default)
    end
  end

  context 'validations' do
    context 'description' do
      it { is_expected.to validate_length_of(:description).is_at_most(4 * (2 ** 10)) }
    end

    context 'name' do
      it { is_expected.to validate_length_of(:name).is_at_most(2**8 - 1) }
      it { is_expected.to validate_presence_of :name }
      it { is_expected.to validate_uniqueness_of :name }
    end
  end

  context 'methods' do
    let(:hosts) do
      FactoryBot.create_list(:mdm_host, 2, :workspace => workspace)
    end

    let(:other_hosts) do
      FactoryBot.create_list(:mdm_host, 2, :workspace => other_workspace)
    end

    let(:other_services) do
      other_hosts.collect do |host|
        FactoryBot.create(:mdm_service, :host => host)
      end
    end

    let(:other_web_sites) do
      other_services.collect { |service|
        FactoryBot.create(:mdm_web_site, :service => service)
      }
    end

    let(:other_workspace) do
      FactoryBot.create(:mdm_workspace)
    end

    let(:services) do
      hosts.collect do |host|
        FactoryBot.create(:mdm_service, :host => host)
      end
    end

    let(:web_sites) do
      services.collect { |service|
        FactoryBot.create(:mdm_web_site, :service => service)
      }
    end

    context '#creds' do
      #
      # Let!s (let + before(:each))
      #

      let!(:creds) do
        services.collect do |service|
          FactoryBot.create(:mdm_cred, :service => service)
        end
      end

      let!(:other_creds) do
        other_services.collect do |service|
          FactoryBot.create(:mdm_cred, :service => service)
        end
      end

      it 'should be an ActiveRecord::Relation' do
        expect(workspace.creds).to be_a ActiveRecord::Relation
      end

      it 'should include services' do
        # to_a to make query return instances
        found_creds = workspace.creds.to_a

        expect(found_creds.length).to be > 0

        expect(
            found_creds.none? { |found_cred|
              found_cred.service.nil?
            }
        ).to eq(true)
      end

      it 'should return only Mdm::Creds from hosts in workspace' do
        found_creds = workspace.creds

        expect(found_creds.length).to eq(creds.length)

        expect(
            found_creds.all? { |cred|
              cred.service.host.workspace == workspace
            }
        ).to eq(true)
      end
    end

    context 'default' do
      context 'with default workspace' do
        before(:example) do
          FactoryBot.create(
              :mdm_workspace,
              :name => default
          )
        end

        it 'should not create workspace' do
          workspace = nil

          expect {
            workspace = described_class.default
          }.to change(Mdm::Workspace, :count).by(0)

          expect(workspace).to be_default
        end
      end

      context 'without default workspace' do
        it 'should create workspace' do
          workspace = nil

          expect {
            workspace = described_class.default
          }.to change(Mdm::Workspace, :count).by(1)

          expect(workspace).to be_default
        end
      end
    end

    context '#default?' do
      subject do
        workspace.default?
      end

      context 'with DEFAULT name' do
        before(:example) do
          workspace.name = default
        end

        it { is_expected.to eq(true) }
      end

      context 'without DEFAULT name' do
        it { is_expected.to eq(false) }
      end
    end

    context '#each_cred' do
      it 'should pass each of the #creds to the block' do
        creds = FactoryBot.create_list(:mdm_cred, 2)
        allow(workspace).to receive(:creds).and_return(creds)

        expect { |block|
          workspace.each_cred(&block)
        }.to yield_successive_args(*creds)
      end
    end

    context '#each_host_tag' do
      it 'should pass each of the #host_tags to the block' do
        tags = FactoryBot.create_list(:mdm_tag, 2)
        expect(workspace).to receive(:host_tags).and_return(tags)

        expect { |block|
          workspace.each_host_tag(&block)
        }.to yield_successive_args(*tags)
      end
    end

    context '#host_tags' do
      let(:host_tags) do
        workspace.host_tags
      end

      #
      # lets
      #

      let(:other_tags) do
        FactoryBot.create_list(
            :mdm_tag,
            2
        )
      end

      let(:tags) do
        FactoryBot.create_list(
            :mdm_tag,
            2
        )
      end

      #
      # Let!s (let + before(:each))
      #

      let!(:first_host_tags) do
        host_tags = []

        hosts.zip(tags) do |host, tag|
          host_tag = FactoryBot.create(:mdm_host_tag, :host => host, :tag => tag)

          host_tags << host_tag
        end

        host_tags
      end

      let!(:second_host_tags) do
        host_tags = []

        other_hosts.zip(other_tags) do |host, tag|
          host_tag = FactoryBot.create(:mdm_host_tag, :host => host, :tag => tag)

          host_tags << host_tag
        end

        host_tags
      end

      it 'should return an ActiveRecord::Relation' do
        expect(workspace.host_tags).to be_a ActiveRecord::Relation
      end

      it 'should return only Mdm::Tags from hosts in the workspace' do
        expect(host_tags.length).to eq(tags.length)

        expect(
            host_tags.all? { |tag|
              tag.hosts.any? { |host|
                host.workspace == workspace
              }
            }
        ).to eq(true)
      end
    end

    context '#normalize' do
      let(:normalize) do
        workspace.send(:normalize)
      end

      before(:example) do
        workspace.boundary = boundary
      end

      context 'with boundary' do
        let(:boundary) do
          " #{stripped_boundary} "
        end

        let(:stripped_boundary) do
          '192.168.0.1'
        end

        it "should remove spaces" do
          normalize

          expect(workspace.boundary).to eq(stripped_boundary)
        end
      end

      context 'without boundary' do
        let(:boundary) do
          nil
        end

        it 'should not raise error' do
          expect {
            normalize
          }.to_not raise_error
        end
      end
    end

    context '#web_forms' do

      subject do
        workspace.web_forms
      end

      #
      # Let!s (let + before(:each))
      #

      let!(:other_web_forms) do
        other_web_sites.collect { |web_site|
          FactoryBot.create(:web_form, :web_site => web_site)
        }
      end

      let!(:web_forms) do
        web_sites.collect { |web_site|
          FactoryBot.create(:web_form, :web_site => web_site)
        }
      end

      it 'should return an ActiveRecord:Relation' do
        is_expected.to be_a ActiveRecord::Relation
      end

      it 'should return only Mdm::WebPages from hosts in the workspace' do
        found_web_forms = workspace.web_forms

        expect(found_web_forms.length).to eq(web_forms.length)

        expect(
            found_web_forms.all? { |web_form|
              web_form.web_site.service.host.workspace == workspace
            }
        ).to eq(true)
      end
    end

    context '#web_sites' do
      subject do
        workspace.web_sites
      end

      #
      # Let!s (let + before(:each))
      #

      before(:example) do
        other_web_sites
        web_sites
      end

      it 'should return an ActiveRecord:Relation' do
        is_expected.to be_a ActiveRecord::Relation
      end

      it 'should return only Mdm::WebVulns from hosts in the workspace' do
        # there are more web sites than those in the workspace
        expect(Mdm::WebSite.count).to be > web_sites.count

        found_web_sites = workspace.web_sites

        expect(found_web_sites.length).to eq(web_sites.count)

        expect(
            found_web_sites.all? { |web_site|
              web_site.service.host.workspace == workspace
            }
        ).to eq(true)
      end
    end

    context '#web_vulns' do
      subject do
        workspace.web_vulns
      end

      #
      # Let!s (let + before(:each))
      #

      let!(:other_web_vulns) do
        other_web_sites.collect { |web_site|
          FactoryBot.create(:mdm_web_vuln, :web_site => web_site)
        }
      end

      let!(:web_vulns) do
        web_sites.collect { |web_site|
          FactoryBot.create(:mdm_web_vuln, :web_site => web_site)
        }
      end

      it 'should return an ActiveRecord:Relation' do
        is_expected.to be_a ActiveRecord::Relation
      end

      it 'should return only Mdm::WebVulns from hosts in the workspace' do
        expect(Mdm::WebVuln.count).to be > web_vulns.length

        found_web_vulns = workspace.web_vulns

        expect(found_web_vulns.length).to eq(web_vulns.length)

        expect(
            found_web_vulns.all? { |web_vuln|
              web_vuln.web_site.service.host.workspace == workspace
            }
        ).to eq(true)
      end
    end

    context '#web_unique_forms' do
      let(:rejected_address) do
        hosts[1].address
      end

      let(:selected_address) do
        hosts[0].address
      end

      it 'should return an ActiveRecord:Relation',
         :pending => 'https://www.pivotaltracker.com/story/show/43219917' do
        is_expected.to be_a ActiveRecord::Relation
      end

      it "should reject #unique_web_forms from host addresses that aren't in addresses" do
        web_forms = workspace.web_unique_forms([selected_address])

        expect(
            web_forms.all? { |web_form|
              expect(web_form.web_site.service.host.address.to_s).to eq(selected_address)
            }
        ).to eq(true)
      end
    end
  end
end
