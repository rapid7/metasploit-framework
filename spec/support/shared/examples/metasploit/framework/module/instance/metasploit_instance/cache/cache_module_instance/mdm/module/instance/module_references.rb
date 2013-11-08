shared_examples_for 'Metasploit::Framework::Module::Instance::MetasploitInstance::Cache#cache_module_instance Mdm::Module::Instance#module_references' do
  subject(:module_references) do
    actual_module_instance.module_references
  end

  it 'should be persisted' do
    with_established_connection do
      module_references.all?(&:persisted?).should be_true
    end
  end

  context 'references' do
    subject(:references) do
      module_references.map(&:reference)
    end

    def reference_attributes(references)
      with_established_connection {
        references.collect { |reference|
          reference.attributes.slice('authority_id', 'designation', 'url')
        }
      }
    end

    it 'should match Msf::Module#references' do
      actual_reference_attributes = reference_attributes(references)
      expected_reference_attributes = reference_attributes(expected_references)

      expect(actual_reference_attributes).to match_array(expected_reference_attributes)
    end
  end

end