require 'spec_helper'

describe Metasploit::Framework::Module::Instance::Synchronization::ModuleAuthors do
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

  let(:formatted_authors) do
    formatted_authors = []

    repeated_name = FactoryGirl.generate :metasploit_model_author_name
    formatted_authors << Msf::Module::Author.new(repeated_name).to_s

    email_address = FactoryGirl.build(:mdm_email_address)
    # validate to derive full
    email_address.valid?
    # same name to ensure (name, email) compaction logic works
    formatted_authors << Msf::Module::Author.new(repeated_name, email_address.full)

    unrepeated_name = FactoryGirl.generate :metasploit_model_author_name
    formatted_authors << Msf::Module::Author.new(unrepeated_name).to_s

    formatted_authors
  end

  let(:metasploit_class) do
    formatted_authors = self.formatted_authors

    Class.new(metasploit_super_class) do
      define_method(:initialize) do |info={}|
        super(
            merge_info(
                info,
                'Author' => formatted_authors
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
        module_authors_length: 0,
        module_class: module_class
    )
  end

  let(:module_type) do
    module_types.sample
  end

  let(:module_types) do
    # exclude payload because it requries a general_handler_type from one of its ancestors
    Metasploit::Model::Module::Type::ALL - ['payload']
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

      it { should be_empty }
    end
  end

  context '#added_author_name_set' do
    subject(:added_author_name_set) do
      synchronization.added_author_name_set
    end

    #
    # lets
    #

    let(:added_attributes_set) do
      expected_author_names.collect { |author_name|
        {
            author: {
                name: author_name
            }
        }
      }
    end

    let(:expected_author_names) do
      2.times.collect {
        FactoryGirl.generate :metasploit_model_author_name
      }
    end

    #
    # callbacks
    #

    before(:each) do
      synchronization.should_receive(:added_attributes_set).and_return(added_attributes_set)
    end

    it 'should include all author names' do
      expect(added_author_name_set.to_a).to match_array(expected_author_names)
    end
  end

  context '#added_email_address_fulls' do
    subject(:added_email_address_full_set) do
      synchronization.added_email_address_full_set
    end

    #
    # lets
    #

    let(:added_attributes_set) do
      Set.new(
          [
              {
                  author: {
                      name: author_name
                  }
              }
          ]
      )
    end

    let(:author_name) do
      FactoryGirl.generate :metasploit_model_author_name
    end

    #
    # callbacks
    #

    before(:each) do
      synchronization.should_receive(:added_attributes_set).and_return(added_attributes_set)
    end

    context 'with :email_address' do
      let(:added_attributes_set) do
        super().tap { |set|
          set.first[:email_address] = {
                full: email_address_full
            }
        }
      end

      let(:email_address) do
        FactoryGirl.build(:mdm_email_address).tap { |email_address|
          # validate to derive #full
          email_address.valid?
        }
      end

      let(:email_address_full) do
        email_address.full
      end

      it 'should contain {email_address: :full} value' do
        added_email_address_full_set.should include(email_address_full)
      end
    end

    context 'without :email_address' do
      it { should_not include(nil) }
    end
  end

  context '#author_by_name' do
    subject(:author_by_name) do
      synchronization.author_by_name
    end

    before(:each) do
      synchronization.stub(added_author_name_set: added_author_name_set)
    end

    context 'with #added_author_name_set' do
      let(:added_author_name_set) do
        2.times.each_with_object(Set.new) { |n, set|
          name = FactoryGirl.generate :metasploit_model_author_name

          set.add name
        }
      end

      context 'without Mdm::Authors' do
        it { should == {} }
      end

      context 'with Mdm::Authors' do
        #
        # lets
        #

        let(:name) do
          added_author_name_set.to_a.sample
        end

        #
        # let!s
        #

        let!(:mdm_author) do
          FactoryGirl.create(
              :mdm_author,
              name: name
          )
        end

        it 'should include existing Mdm::Authors' do
          author_by_name[mdm_author.name].should == mdm_author
        end

        context 'with unknown name' do
          let(:name) do
            FactoryGirl.generate :metasploit_model_author_name
          end

          it 'should make a new Mdm::Author' do
            new_author = author_by_name[name]

            new_author.should be_a_new_record
            new_author.name.should == name
          end
        end
      end
    end

    context 'without #added_author_name_set' do
      let(:added_author_name_set) do
        Set.new
      end

      it { should == {} }

      it 'should not query Mdm::Author' do
        Mdm::Author.should_not_receive(:where)

        author_by_name
      end

      context 'with unknown name' do
        let(:name) do
          FactoryGirl.generate :metasploit_model_author_name
        end

        it 'should make a new Mdm::Author' do
          new_author = author_by_name[name]

          new_author.should be_a_new_record
          new_author.name.should == name
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
              {
                  author: {
                      name: author_name
                  }
              }
          ]
      )
    end

    let(:author_name) do
      FactoryGirl.generate :metasploit_model_author_name
    end

    let(:built_module_author) do
      module_instance.module_authors.first
    end

    #
    # callbacks
    #

    before(:each) do
      synchronization.stub(added_attributes_set: added_attributes_set)
    end

    it 'should look up [:author][:name] in #author_by_name' do
      synchronization.author_by_name.should_receive(:[]).with(author_name)

      build_added
    end

    it 'should build #destination #module_authors with author' do
      build_added
      author = built_module_author.author

      author.should_not be_nil
      author.name.should == author_name
    end

    context 'with :email_address' do
      let(:added_attributes_set) do
        super().tap { |set|
          set.first[:email_address] = {
              full: email_address_full
          }
        }
      end

      let(:email_address) do
        FactoryGirl.build(:mdm_email_address).tap { |email_address|
          # validate to derive #full
          email_address.valid?
        }
      end

      let(:email_address_full) do
        email_address.full
      end

      it 'should build #destination #module_authors with non-nil email_address' do
        build_added
        email_address = built_module_author.email_address

        email_address.should_not be_nil
        email_address.full.should == email_address_full
      end
    end

    context 'without :email_address' do
      it 'should build #destination #module_authors with nil email_address' do
        build_added

        built_module_author.email_address.should be_nil
      end
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

      it { should be_true }
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

      it { should be_true }
    end

    context 'with payload' do
      let(:module_type) do
        'payload'
      end

      it { should be_true }
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
    end

    context 'without new record' do
      #
      # lets
      #

      let(:author) do
        FactoryGirl.create(:mdm_author)
      end

      let(:email_address) do
        nil
      end

      let(:module_instance) do
        super().tap { |module_instance|
          module_instance.module_authors.build(
              author: author,
              email_address: email_address
          )
        }
      end

      #
      # callbacks
      #

      before(:each) do
        module_instance.save!
      end

      context 'module_authors' do
        it 'should have author.name' do
          destination_attributes_set.any? { |attributes|
            attributes[:author][:name] == author.name
          }.should be_true
        end

        context 'with email_address' do
          let(:email_address) do
            FactoryGirl.create(:mdm_email_address)
          end

          it 'should include email_address.full' do
            destination_attributes_set.any? { |attributes|
              email_address_attributes = attributes[:email_address]

              if email_address_attributes
                email_address_attributes[:full] == email_address.full
              else
                false
              end
            }.should be_true
          end
        end

        context 'without email_address' do
          it 'should not include :email_address' do
            destination_attributes_set.none? { |attributes|
              attributes.has_key? :email_address
            }.should be_true
          end
        end
      end
    end
  end

  context '#destroy_removed' do
    subject(:destroy_removed) do
      synchronization.destroy_removed
    end

    context 'with new record' do
      it 'should not call destroy_all' do
        ActiveRecord::Relation.should_not_receive(:destroy_all)

        destroy_removed
      end
    end

    context 'without new record' do
      let(:author) do
        FactoryGirl.create(:mdm_author)
      end

      let(:email_address) do
        nil
      end

      let(:module_instance) do
        super().tap { |module_instance|
          module_instance.module_authors.build(
              author: author,
              email_address: email_address
          )
        }
      end

      before(:each) do
        module_instance.save!

        synchronization.stub(removed_attributes_set: removed_attributes_set)
      end

      context 'with #removed_attributes_set' do
        context 'with same email address used with multiple names' do
          let(:email_address) do
            FactoryGirl.create(:mdm_email_address)
          end

          let(:module_instance) do
            super().tap { |module_instance|
              module_instance.module_authors.build(
                  author: second_author,
                  email_address: email_address
              )
            }
          end

          let(:removed_attributes_set) do
            Set.new(
                [
                    {
                        author: {
                            name: second_author.name
                        },
                        email_address: {
                            full: email_address.full
                        }
                    }
                ]
            )
          end

          let(:second_author) do
            FactoryGirl.create(:mdm_author)
          end

          it 'should destroy Mdm::Module::Author with (author, email_address)' do
            destroy_removed

            module_instance.module_authors.where(
                author_id: second_author.id,
                email_address_id: email_address.id
            ).should_not exist
          end

          it 'should not destroy Mdm::Module::Author with (?, email_address)' do
            destroy_removed

            module_instance.module_authors.where(
                author_id: author.id,
                email_address_id: email_address.id
            ).should exist
          end
        end
      end

      context 'without #removed_attributes_set' do
        let(:removed_attributes_set) do
          Set.new
        end

        it 'should not call destroy_all' do
          ActiveRecord::Relation.should_not_receive(:destroy_all)

          destroy_removed
        end
      end
    end
  end

  context '#email_address_by_full' do
    subject(:email_address_by_full) do
      synchronization.email_address_by_full
    end

    before(:each) do
      synchronization.stub(added_email_address_full_set: added_email_address_full_set)
    end

    context 'with #added_email_address_full_set' do
      let(:added_email_address_full_set) do
        Set.new(
            [
                email_address_full
            ]
        )
      end

      let(:email_address_domain) do
        FactoryGirl.generate :metasploit_model_email_address_domain
      end

      let(:email_address_full) do
        "#{email_address_local}@#{email_address_domain}"
      end

      let(:email_address_local) do
        FactoryGirl.generate :metasploit_model_email_address_local
      end

      context 'with matching Mdm::EmailAddress' do
        #
        # lets
        #

        let(:email_address_full) do
          email_address.full
        end

        #
        # let!s
        #

        let!(:email_address) do
          FactoryGirl.create(:mdm_email_address)
        end

        it 'should include Mdm::EmailAddress' do
          email_address_by_full[email_address_full].should == email_address
        end
      end

      context 'without matching Mdm::EmailAddress' do
        it { should be_empty }
      end

      context 'with unknown Mdm::EmailAddress#full' do
        let(:unknown_domain) do
          FactoryGirl.generate :metasploit_model_email_address_domain
        end

        let(:unknown_full) do
          "#{unknown_local}@#{unknown_domain}"
        end

        let(:unknown_local) do
          FactoryGirl.generate :metasploit_model_email_address_local
        end

        it 'should build a new Mdm::EmailAddress' do
          email_address = email_address_by_full[unknown_full]

          email_address.should_not be_nil
          email_address.full.should == unknown_full
        end
      end
    end

    context 'without #added_email_address_full_set' do
      let(:added_email_address_full_set) do
        Set.new
      end

      it { should be_empty }

      context 'with unknown Mdm::EmailAddress#full' do
        let(:domain) do
          FactoryGirl.generate :metasploit_model_email_address_domain
        end

        let(:full) do
          "#{local}@#{domain}"
        end

        let(:local) do
          FactoryGirl.generate :metasploit_model_email_address_local
        end

        it 'should build a new Mdm::EmailAddress' do
          email_address = email_address_by_full[full]

          email_address.should_not be_nil
          email_address.full.should == full
        end
      end
    end
  end

  context '#scope' do
    subject(:scope) do
      synchronization.scope
    end

    it 'should include :author' do
      scope.includes_values.should include(:author)
    end

    it 'should include :email_address' do
      scope.includes_values.should include(:email_address)
    end
  end

  context '#source_authors' do
    subject(:source_authors) do
      synchronization.source_authors
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
        metasploit_instance.should_receive(:authors).and_raise(error)
      end

      it 'should log module instance error' do
        synchronization.should_receive(:log_module_instance_error).with(module_instance, error)

        source_authors
      end

      it { should == [] }
    end

    context 'without NoMethodError' do
      it 'should be #source #authors' do
        source_authors.should == metasploit_instance.authors
      end
    end
  end

  context '#source_attributes_set' do
    subject(:source_attributes_set) do
      synchronization.source_attributes_set
    end

    #
    # lets
    #

    let(:msf_module_author) do
      Msf::Module::Author.new(name)
    end

    let(:name) do
      FactoryGirl.generate :metasploit_model_author_name
    end

    let(:source_authors) do
      [
          msf_module_author
      ]
    end

    #
    # callbacks
    #

    before(:each) do
      synchronization.stub(source_authors: source_authors)
    end

    it 'should include {author: :name} value' do
      source_attributes_set.any? { |source_attributes|
        author_attributes = source_attributes[:author]

        author_attributes.should_not be_nil
        author_attributes[:name] == name
      }.should be_true
    end

    context 'with email' do
      let(:email) do
        "#{email_local}@#{email_domain}"
      end

      let(:email_domain) do
        FactoryGirl.generate :metasploit_model_email_address_domain
      end

      let(:email_local) do
        FactoryGirl.generate :metasploit_model_email_address_local
      end

      let(:msf_module_author) do
        Msf::Module::Author.new(name, email)
      end

      it 'should include {email_address: full} value' do
        source_attributes_set.any? { |source_attributes|
          email_address_attributes = source_attributes[:email_address]

          if email_address_attributes
            email_address_attributes[:full] == email
          else
            false
          end
        }.should be_true
      end
    end

    context 'without email' do
      it 'should not include :email_address' do
        source_attributes_set.should_not be_empty

        source_attributes_set.none? { |source_attributes|
          source_attributes.has_key? :email_address
        }.should be_true
      end
    end
  end

  context '#synchronize' do
    subject(:synchronize) do
      synchronization.synchronize
    end

    it 'should destroy removed and then build added' do
      synchronization.should_receive(:destroy_removed).ordered
      synchronization.should_receive(:build_added).ordered

      synchronize
    end
  end
end