shared_examples_for 'Metasploit::Framework::Module::Instance::MetasploitInstance::Cache#cache_module_instance Mdm::Module::Instance' do
  context '#description' do
    subject(:description) do
      actual_module_instance.description
    end

    it 'should match Msf::Module#description' do
      description.should == expected_module_instance.description
    end
  end

  context '#license' do
    subject(:license) do
      actual_module_instance.license
    end

    it 'should match Msf::Module#license' do
      license.should == expected_module_instance.license
    end
  end

  context '#module_authors' do
    subject(:module_authors) do
      actual_module_instance.module_authors
    end

    def module_author_attributes(module_authors)
      module_authors.collect { |module_author|
        name = module_author.author.name

        email_address = module_author.email_address
        email = nil

        if email_address
          email = email_address.full
        end

        {
            name: name,
            email: email
        }
      }
    end

    it 'should match Msf::Module#authors' do
      actual_module_author_attributes = module_author_attributes(module_authors)

      expected_module_author_attributes = base_instance.authors.collect { |author|
        email = author.email

        if email.blank?
          email = nil
        end

        {
            email: email,
            name: author.name
        }
      }

      expect(actual_module_author_attributes).to match_array(expected_module_author_attributes)
    end

    it 'should be persisted' do
      module_authors.all?(&:persisted?).should be_true
    end
  end

  context '#name' do
    subject(:name) do
      actual_module_instance.name
    end

    it 'should match Msf::Module#name' do
      name.should == expected_module_instance.name
    end
  end
end