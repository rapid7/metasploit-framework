require 'spec_helper'

describe Metasploit::Framework::Module::Instance::Synchronization::ModuleReferences do
  include_context 'database seeds'
  include_context 'metasploit_super_class_by_module_type'
  include_context 'Msf::Simple::Framework'

  subject(:synchronization) do
    described_class.new(
        destination: module_instance,
        source: metasploit_instance
    )
  end

  #
  # lets
  #

  let(:expected_reference) do
    FactoryGirl.build(:mdm_reference)
  end

  let(:expected_references) do
    [
        expected_reference,
        expected_url_reference
    ]
  end

  let(:expected_url_reference) do
    FactoryGirl.build(:url_mdm_reference)
  end

  let(:formatted_references) do
    expected_references.collect { |reference|
      authority =  reference.authority

      if authority
        [authority.abbreviation, reference.designation]
      else
        ['URL', reference.url]
      end
    }
  end

  let(:metasploit_class) do
    formatted_references = self.formatted_references

    Class.new(metasploit_super_class) do
      define_method(:initialize) do |info={}|
        super(
            merge_info(
                info,
                'References' => formatted_references
            )
        )
      end
    end
  end

  let(:metasploit_instance) do
    metasploit_class.new(
        framework: framework
    )
  end

  let(:module_class) do
    FactoryGirl.create(
        :mdm_module_class,
        module_type: module_type
    )
  end

  let(:module_instance) do
    FactoryGirl.build(
        :mdm_module_instance,
        module_references_length: 0,
        module_class: module_class
    )
  end

  let(:module_type) do
    module_types.sample
  end

  let(:module_types) do
    Metasploit::Model::Module::Instance.module_types_that_allow(:module_references)
  end

  #
  # callbacks
  #

  around(:each) do |example|
    with_established_connection do
      example.run
    end
  end

  context 'CONSTANTS' do
    context 'ALLOW_BY_ATTRIBUTE' do
      subject(:allow_by_attribute) do
        described_class::ALLOW_BY_ATTRIBUTE
      end

      its([:module_references]) { should be_true }
    end
  end

  context '#added_authority_abbreviation_set' do
    subject(:added_authority_abbreviation_set) do
      synchronization.added_authority_abbreviation_set
    end

    #
    # lets
    #

    let(:added_attributes_set) do
      Set.new(
          [
              {
                  authority: {
                      abbreviation: authority_abbreviation
                  }
              },
              {}
          ]
      )
    end

    let(:authority) do
      FactoryGirl.generate :seeded_mdm_authority
    end

    let(:authority_abbreviation) do
      authority.abbreviation
    end

    #
    # callbacks
    #

    before(:each) do
      synchronization.stub(added_attributes_set: added_attributes_set)
    end

    it { should be_a Set }
    it { should_not include(nil) }

    it 'should include :authority :abbreviation' do
      added_authority_abbreviation_set.should include(authority_abbreviation)
    end
  end

  context '#authority_by_abbreviation' do
    subject(:authority_by_abbreviation) do
      synchronization.authority_by_abbreviation
    end

    before(:each) do
      synchronization.stub(added_authority_abbreviation_set: added_authority_abbreviation_set)
    end

    context 'with #added_authority_abbreviation_set' do
      let(:added_authority_abbreviation_set) do
        Set.new(
            [
                authority_abbreviation
            ]
        )
      end

      let(:authority_abbreviation) do
        FactoryGirl.generate :metasploit_model_authority_abbreviation
      end

      context 'with Mdm::Authority' do
        #
        # lets
        #

        let(:authority_abbreviation) do
          authority.abbreviation
        end

        #
        # let!s
        #

        let!(:authority) do
          FactoryGirl.create(
              :mdm_authority
          )
        end

        it 'should include Mdm::Authority' do
          authority_by_abbreviation[authority_abbreviation].should == authority
        end
      end

      context 'without Mdm::Authority' do
        it { should be_empty }
      end

      context 'with unknown abbreviation' do
        let(:unknown_abbreviation) do
          FactoryGirl.generate :metasploit_model_authority_abbreviation
        end

        it 'should build a new Mdm::Authority' do
          authority = authority_by_abbreviation[unknown_abbreviation]

          authority.should_not be_nil
          authority.abbreviation.should == unknown_abbreviation
        end
      end
    end

    context 'without #added_authority_abbreviation_set' do
      let(:added_authority_abbreviation_set) do
        Set.new
      end

      it { should == {} }

      context 'with unknown abbreviation' do
        let(:unknown_abbreviation) do
          FactoryGirl.generate :metasploit_model_authority_abbreviation
        end

        it 'should build a new Mdm::Authority' do
          authority = authority_by_abbreviation[unknown_abbreviation]

          authority.should_not be_nil
          authority.abbreviation.should == unknown_abbreviation
        end
      end
    end
  end

  context '#build_added' do
    subject(:build_added) do
      synchronization.build_added
    end

    #
    # lets
    #

    let(:added_attributes_set) do
      Set.new(
          [
              attributes
          ]
      )
    end

    let(:attributes) do
      {
          url: url
      }
    end

    let(:url) do
      FactoryGirl.generate :metasploit_model_reference_url
    end

    #
    # callbacks
    #

    before(:each) do
      synchronization.stub(added_attributes_set: added_attributes_set)
    end

    it 'should lookup reference in #reference_by_attributes' do
      synchronization.reference_by_attributes.should_receive(:[]).with(attributes).and_call_original

      build_added
    end

    it 'should build module_reference' do
      build_added

      module_reference = module_instance.module_references.first
      module_reference.reference.url.should == url
    end
  end


  context 'can_synchronize?' do
    subject(:can_synchronize?) do
      described_class.can_synchronize?(module_instance)
    end

    context 'with auxiliary' do
      let(:module_type) do
        'auxiliary'
      end

      it { should be_true }
    end

    context 'with encoder' do
      let(:module_type) do
        'encoder'
      end

      it { should be_false }
    end

    context 'with exploit' do
      let(:module_type) do
        'exploit'
      end

      it { should be_true }
    end

    context 'with nop' do
      let(:module_type) do
        'nop'
      end

      it { should be_false }
    end

    context 'with payload' do
      let(:module_type) do
        'payload'
      end

      it { should be_false }
    end

    context 'with post' do
      let(:module_type) do
        'post'
      end

      it { should be_true }
    end
  end

  context '#destination_attributes_set' do
    subject(:destination_attributes_set) do
      synchronization.destination_attributes_set
    end

    context 'with new record' do
      it { should == Set.new }

      it 'should not query database' do
        synchronization.should_not_receive(:scope)

        destination_attributes_set
      end
    end

    context 'without new record' do
      #
      # lets
      #

      let(:module_instance) do
        super().tap { |module_instance|
          module_instance.module_references.build(
              reference: reference
          )
        }
      end

      let(:reference) do
        FactoryGirl.create(:mdm_reference)
      end

      #
      # callbacks
      #

      before(:each) do
        module_instance.save!
      end

      it { should be_a Set }

      context 'with authority' do
        let(:reference) do
          FactoryGirl.create(:mdm_reference)
        end

        it 'should include {authority: :abbreviation} and :designation' do
          destination_attributes_set.any? { |destination_attributes|
            authority = destination_attributes[:authority]

            if authority
              if authority[:abbreviation] == reference.authority.abbreviation &&
                 destination_attributes[:designation] == reference.designation
                true
              else
                false
              end
            else
              false
            end
          }.should be_true
        end

        it 'should not include :url' do
          destination_attributes_set.none? { |destination_attributes|
            destination_attributes.has_key? :url
          }.should be_true
        end
      end

      context 'without authority' do
        let(:reference) do
          FactoryGirl.create(:url_mdm_reference)
        end

        it 'should include :url' do
          destination_attributes_set.any? { |destination_attributes|
            destination_attributes[:url] == reference.url
          }.should be_true
        end

        it 'should not include :authority' do
          destination_attributes_set.none? { |destination_attributes|
            destination_attributes.has_key? :authority
          }.should be_true
        end

         it 'should not include :designation' do
          destination_attributes_set.none? { |destination_attributes|
            destination_attributes.has_key? :designation
          }.should be_true
        end
      end
    end
  end

  context '#destroy_removed' do
    subject(:destroy_removed) do
      synchronization.destroy_removed
    end

    context 'with new record' do
      it 'should not destroy anything' do
        ActiveRecord::Relation.any_instance.should_not_receive(:destroy_all)

        destroy_removed
      end
    end

    context 'without new record' do
      let(:module_instance) do
        super().tap { |module_instance|
          expected_references.each do |reference|
            module_instance.module_references.build(
                reference: reference
            )
          end
        }
      end

      before(:each) do
        module_instance.save!

        synchronization.stub(removed_attributes_set: removed_attributes_set)
      end

      context 'with #removed_attributes_set' do
        let(:abbreviation) do
          expected_reference.authority.abbreviation
        end

        let(:designation) do
          expected_reference.designation
        end

        let(:removed_attributes_set) do
          Set.new(
              [
                  {
                      authority: {
                          abbreviation: abbreviation
                      },
                      designation: designation
                  },
                  {
                      url: url
                  }
              ]
          )
        end

        let(:url) do
          expected_url_reference.url
        end

        it 'should destroy (authority, designation) reference' do
          expect {
            destroy_removed
          }.to change {
            module_instance.module_references.joins(reference: :authority).where(
                Mdm::Authority.arel_table[:abbreviation].eq(abbreviation).and(
                    Mdm::Reference.arel_table[:designation].eq(designation)
                )
            ).exists?
          }.to(false)
        end

        it 'should destroy (url) reference' do
          expect {
            destroy_removed
          }.to change {
            module_instance.module_references.joins(:reference).where(
                Mdm::Reference.arel_table[:url].eq(url)
            ).exists?
          }.to(false)
        end
      end

      context 'without #removed_attribute_set' do
        let(:removed_attributes_set) do
          Set.new
        end

        it 'should not destroy anything' do
          ActiveRecord::Relation.any_instance.should_not_receive(:destroy_all)

          destroy_removed
        end
      end
    end
  end

  context '#destroy_removed_condition' do
    subject(:destroy_removed_condition) do
      synchronization.destroy_removed_condition
    end

    #
    # lets
    #

    let(:abbreviation) do
      FactoryGirl.generate :metasploit_model_authority_abbreviation
    end

    let(:designation) do
      FactoryGirl.generate :metasploit_model_reference_designation
    end

    let(:designation_condition) do
      Mdm::Reference.arel_table[:designation].eq(designation).and(
          Mdm::Authority.arel_table[:abbreviation].eq(abbreviation)
      )
    end

    let(:removed_attributes_set_conditions) do
      [
          url_condition,
          designation_condition
      ]
    end

    let(:url) do
      FactoryGirl.generate :metasploit_model_reference_url
    end

    let(:url_condition) do
      Mdm::Reference.arel_table[:url].eq(url)
    end

    #
    # Callbacks
    #

    before(:each) do
      synchronization.stub(removed_attributes_set_conditions: removed_attributes_set_conditions)
    end

    it 'should OR together #removed_attributes_set_conditions' do
      destroy_removed_condition.to_sql.should == "(#{url_condition.to_sql} OR #{designation_condition.to_sql})"
    end
  end

  context '#reference_condition' do
    subject(:reference_condition) do
      synchronization.reference_condition
    end

    #
    # lets
    #

    let(:authority_id) do
      Random.rand(1 .. 1000)
    end

    let(:designation) do
      FactoryGirl.generate :metasploit_model_reference_designation
    end

    let(:designation_condition) do
      Mdm::Reference.arel_table[:authority_id].eq(authority_id).and(
          Mdm::Reference.arel_table[:designation].eq(designation)
      )
    end

    let(:reference_conditions) do
      [
          designation_condition,
          url_condition
      ]
    end

    let(:url) do
      FactoryGirl.generate :metasploit_model_reference_url
    end

    let(:url_condition) do
      Mdm::Reference.arel_table[:url].eq(url)
    end

    #
    # callbacks
    #

    before(:each) do
      synchronization.stub(reference_conditions: reference_conditions)
    end

    it 'should OR together #reference_conditons' do
      reference_condition.to_sql.should == "(#{designation_condition.to_sql} OR #{url_condition.to_sql})"
    end
  end

  context '#reference_by_attributes' do
    subject(:reference_by_attributes) do
      synchronization.reference_by_attributes
    end

    before(:each) do
      synchronization.stub(reference_condition: reference_condition)
    end

    shared_examples_for 'with unknown attributes' do
      subject(:built_reference) do
        reference_by_attributes[attributes]
      end

      context 'with :authority' do
        let(:abbreviation) do
          FactoryGirl.generate :metasploit_model_authority_abbreviation
        end

        let(:attributes) do
          {
              authority: {
                  abbreviation: abbreviation
              },
              designation: designation
          }
        end

        let(:designation) do
          FactoryGirl.generate :metasploit_model_reference_designation
        end

        it 'should build Mdm::Reference with (authority, designation)' do
          built_reference.should_not be_nil
          built_reference.should be_a_new_record
          built_reference.authority.should_not be_nil
          built_reference.authority.abbreviation.should == abbreviation
          built_reference.designation.should == designation
        end
      end

      context 'without :authority' do
        let(:attributes) do
          {
              url: url
          }
        end

        let(:url) do
          FactoryGirl.generate :metasploit_model_reference_url
        end

        it 'should build Mdm::Reference with url' do
          built_reference.should_not be_nil
          built_reference.should be_new_record
          built_reference.url.should == url
        end
      end
    end

    context 'with #reference_condition' do
      let(:abbreviation) do
        FactoryGirl.generate :metasploit_model_authority_abbreviation
      end

      let(:designation) do
        FactoryGirl.generate :metasploit_model_reference_designation
      end

      let(:url) do
        FactoryGirl.generate :metasploit_model_reference_url
      end

      let(:reference_condition) do
        Mdm::Authority.arel_table[:abbreviation].eq(abbreviation).and(
            Mdm::Reference.arel_table[:designation].eq(designation)
        ).or(
            Mdm::Reference.arel_table[:url].eq(url)
        )
      end

      context 'with matching Mdm::Reference' do
        subject(:found_reference) do
          reference_by_attributes[attributes]
        end

        context 'on authority abbreviation and designation' do
          #
          # lets
          #

          let(:attributes) do
            {
                authority: {
                    abbreviation: abbreviation
                },
                designation: designation
            }
          end

          #
          # let!s
          #

          let!(:authority) do
            FactoryGirl.create(
                :mdm_authority,
                abbreviation: abbreviation
            )
          end

          let!(:reference) do
            FactoryGirl.create(
                :mdm_reference,
                authority: authority,
                designation: designation
            )
          end

          it 'should include the matching Mdm::Reference' do
            found_reference.should == reference
          end
        end

        context 'on url' do
          #
          # lets
          #

          let(:attributes) do
            {
                url: url
            }
          end

          #
          # let!s
          #

          let!(:reference) do
            FactoryGirl.create(
                :url_mdm_reference,
                url: url
            )
          end

          it 'should include matching Mdm::Reference' do
            found_reference.should == reference
          end
        end
      end

      context 'without matching Mdm::Reference' do
        it { should be_empty }
      end

      it_should_behave_like 'with unknown attributes'
    end

    context 'without #reference_condition' do
      let(:reference_condition) do
        nil
      end

      it { should be_empty }

      it_should_behave_like 'with unknown attributes'
    end
  end

  context '#reference_conditions' do
    subject(:reference_conditions) do
      synchronization.reference_conditions
    end

    let(:added_attributes_set) do
      Set.new(
          [
              attributes
          ]
      )
    end


    before(:each) do
      synchronization.stub(added_attributes_set: added_attributes_set)
    end

    context 'with :authority' do
      let(:abbreviation) do
        FactoryGirl.generate :metasploit_model_authority_abbreviation
      end

      let(:attributes) do
        {
            authority: {
                abbreviation: abbreviation
            },
            designation: designation
        }
      end

      let(:designation) do
        FactoryGirl.generate :metasploit_model_reference_designation
      end

      it 'should get Mdm::Authority from #authority_by_abbreviation' do
        synchronization.authority_by_abbreviation.should_receive(:[]).with(abbreviation).and_call_original

        reference_conditions
      end

      context 'with new Mdm::Authority' do
        it 'should not include condition' do
          reference_conditions.should be_empty
        end
      end

      context 'without new Mdm::Authority' do
        let!(:authority) do
          FactoryGirl.create(
              :mdm_authority,
              abbreviation: abbreviation
          )
        end

        it 'should include condition' do
          expected_condition = Mdm::Reference.arel_table[:authority_id].eq(authority.id).and(
              Mdm::Reference.arel_table[:designation].eq(designation)
          )
          expected_sql = expected_condition.to_sql

          reference_conditions.any? { |condition|
            # AREL conditions don't compare with ==, so need to convert to SQL
            condition.to_sql.should == expected_sql
          }.should be_true
        end
      end
    end

    context 'without :authority' do
      let(:attributes) do
        {
            url: url
        }
      end

      let(:url) do
        FactoryGirl.generate :metasploit_model_reference_url
      end

      it 'should include condition on url' do
        expected_condition = Mdm::Reference.arel_table[:url].eq(url)
        expected_sql = expected_condition.to_sql

        reference_conditions.any? { |condition|
          # AREL conditions don't compare with ==, so need to convert to SQL
          condition.to_sql.should == expected_sql
        }.should be_true
      end
    end
  end

  context '#removed_attributes_set_conditions' do
    subject(:removed_attributes_set_conditions) do
      synchronization.removed_attributes_set_conditions
    end

    #
    # lets
    #

    let(:removed_attributes_set) do
      Set.new(
          [
              attributes
          ]
      )
    end

    #
    # callbacks
    #

    before(:each) do
      synchronization.stub(removed_attributes_set: removed_attributes_set)
    end

    context 'with :url' do
      let(:attributes) do
        {
            url: url
        }
      end

      let(:url) do
        FactoryGirl.generate :metasploit_model_reference_url
      end

      it 'should include condition on url' do
        expected_condition = Mdm::Reference.arel_table[:url].eq(url)
        expected_sql = expected_condition.to_sql

        removed_attributes_set_conditions.any? { |condition|
          condition.to_sql.should == expected_sql
        }.should be_true
      end
    end

    context 'without :url' do
      let(:abbreviation) do
        FactoryGirl.generate :metasploit_model_authority_abbreviation
      end

      let(:attributes) do
        {
            authority: {
                abbreviation: abbreviation
            },
            designation: designation
        }
      end

      let(:designation) do
        FactoryGirl.generate :metasploit_model_reference_designation
      end

      it 'should include condition on authority abbreviation and designation' do
        expected_condition = Mdm::Reference.arel_table[:designation].eq(designation).and(
            Mdm::Authority.arel_table[:abbreviation].eq(abbreviation)
        )
        expected_sql = expected_condition.to_sql

        removed_attributes_set_conditions.any? { |condition|
          condition.to_sql == expected_sql
        }.should be_true
      end
    end
  end

  context '#scope' do
    subject(:scope) do
      synchronization.scope
    end

    context 'includes' do
      subject(:includes) do
        scope.includes_values
      end

      it { should include(reference: :authority) }
    end
  end

  context '#synchronize' do
    subject(:synchronize) do
      synchronization.synchronize
    end

    it 'should destroy removed and build added' do
      synchronization.should_receive(:destroy_removed).ordered
      synchronization.should_receive(:build_added).ordered

      synchronize
    end
  end

  context '#source_attributes_set' do
    subject(:source_attributes_set) do
      synchronization.source_attributes_set
    end

    #
    # lets
    #

    let(:source_references) do
      []
    end

    #
    # callbacks
    #

    before(:each) do
      synchronization.stub(source_references: source_references)
    end

    it { should be_a Set }

    context 'with Msf::Module::SiteReference' do
      let(:source_references) do
        [
            Msf::Module::SiteReference.from_a(array)
        ]
      end

      context 'with URL' do
        let(:array) do
          [
              'URL',
              url
          ]
        end

        let(:url) do
          FactoryGirl.generate :metasploit_model_reference_url
        end

        it 'should include :url' do
          source_attributes_set.should include(url: url)
        end
      end

      context 'without URL' do
        let(:abbreviation) do
          FactoryGirl.generate :metasploit_model_authority_abbreviation
        end

        let(:array) do
          [
              abbreviation,
              designation
          ]
        end

        let(:designation) do
          FactoryGirl.generate :metasploit_model_reference_designation
        end

        it 'should include :authority :abbreviation and :designation' do
          source_attributes_set.should include(
              authority: {
                  abbreviation: abbreviation
              },
              designation: designation
                                   )
        end
      end
    end

    context 'with Msf::Module::Reference' do
      let(:source_references) do
        [
            Msf::Module::Reference.new("a reference")
        ]
      end

      specify {
        expect {
          source_attributes_set
        }.to raise_error(NotImplementedError)
      }
    end

    context 'with other' do
      let(:source_references) do
        [
            double('Other')
        ]
      end

      specify {
        expect {
          source_attributes_set
        }.to raise_error(ArgumentError)
      }
    end
  end

  context '#source_references' do
    subject(:source_references) do
      synchronization.source_references
    end

    context 'with NoMethodError' do
      #
      # lets
      #

      let(:error) do
        NoMethodError.new('message')
      end

      #
      # callbacks
      #

      before(:each) do
        metasploit_instance.should_receive(:references).and_raise(error)
      end

      it { should == [] }

      it 'should log module instance error' do
        synchronization.should_receive(:log_module_instance_error).with(module_instance, error)

        source_references
      end
    end

    context 'without NoMethodError' do
      it 'should be source.references' do
        source_references.should == metasploit_instance.references
      end
    end
  end
end