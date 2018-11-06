RSpec.describe MetasploitDataModels::ModuleRun, type: :model do

  subject(:module_run){FactoryBot.build(:metasploit_data_models_module_run)}

  context "database columns" do
    it { is_expected.to have_db_column(:attempted_at).of_type(:datetime) }
    it { is_expected.to have_db_column(:fail_detail).of_type(:text) }
    it { is_expected.to have_db_column(:fail_reason).of_type(:string) }
    it { is_expected.to have_db_column(:module_fullname).of_type(:text) }
    it { is_expected.to have_db_column(:port).of_type(:integer) }
    it { is_expected.to have_db_column(:proto).of_type(:string) }
    it { is_expected.to have_db_column(:session_id).of_type(:integer) }
    it { is_expected.to have_db_column(:status).of_type(:string) }
    it { is_expected.to have_db_column(:trackable_id).of_type(:integer) }
    it { is_expected.to have_db_column(:trackable_type).of_type(:string) }
    it { is_expected.to have_db_column(:user_id).of_type(:integer) }
    it { is_expected.to have_db_column(:username).of_type(:string) }
  end

  context "associations" do
    it { is_expected.to belong_to(:user).class_name('Mdm::User') }
    it { is_expected.to belong_to(:user).inverse_of(:module_runs) }
    it { is_expected.to belong_to(:target_session).class_name('Mdm::Session') }
    it { is_expected.to belong_to(:target_session).inverse_of(:target_module_runs) }
    it { is_expected.to belong_to(:trackable) }
    it { is_expected.to belong_to(:module_detail).class_name('Mdm::Module::Detail') }
    it { is_expected.to belong_to(:module_detail).inverse_of(:module_runs) }
    it { is_expected.to have_many(:loots).class_name('Mdm::Loot') }
    it { is_expected.to have_many(:loots).inverse_of(:module_run) }
    it { is_expected.to have_one(:spawned_session).class_name('Mdm::Session') }
    it { is_expected.to have_one(:spawned_session).inverse_of(:originating_module_run) }
  end

  context "validations" do
    describe "when a target_session is set on the module run" do
      before(:example) do
        module_run.target_session = FactoryBot.build(:mdm_session)
      end

      context "when the module is an exploit" do
        context "and that exploit IS NOT local" do
          before(:example) do
            module_run.module_fullname = 'exploit/windows/mah-crazy-exploit'
          end

          it { is_expected.to_not be_valid }
        end

        context "and that exploit IS local" do
          before(:example) do
            module_run.module_fullname = 'exploit/windows/local/mah-crazy-exploit'
          end

          it { is_expected.to be_valid }
        end
      end
    end

    describe "when a spawned_session is set on the module run" do
      before(:example) do
        module_run.spawned_session  = FactoryBot.build(:mdm_session)
      end

      context "when the module is not an exploit" do

        context "and it IS NOT a login scanner" do
          before(:example) do
            module_run.module_fullname = 'post/multi/gather/steal-minecraft-maps'
          end

          it { is_expected.to_not be_valid }
        end

        context "and it IS a login scanner" do
          before(:example) do
            module_run.module_fullname = 'auxiliary/scanner/ssh/ssh_login'
          end

          it { is_expected.to be_valid }
        end
      end
    end

    describe "attempted_at" do
      before(:example){ module_run.attempted_at = nil }

      it { is_expected.to_not be_valid } 
    end

    describe "content information" do
      context "when there is no module_name" do
        before(:example) do
          module_run.module_fullname = nil
        end

        it { is_expected.to_not be_valid }
      end
    end


    describe "status" do
      describe "invalidity" do
        before(:example) do
          module_run.status = "invalid nonsense"
        end

        it { expect(module_run).to_not be_valid}
      end

      describe "validity" do
        context "when the module run succeeded" do
          before(:example){ module_run.status = MetasploitDataModels::ModuleRun::SUCCEED}

          it{ expect(module_run).to be_valid }
        end

        context "when the module run went normally but failed" do
          before(:example){ module_run.status = MetasploitDataModels::ModuleRun::FAIL}

          it{ expect(module_run).to be_valid }
        end

        context "when the module run errored out" do
          before(:example){ module_run.status = MetasploitDataModels::ModuleRun::ERROR}

          it{ expect(module_run).to be_valid }
        end

      end

    end
  end
end

