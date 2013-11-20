shared_examples_for 'Metasploit::Framework::Synchronizes#synchronizes' do |*attributes_and_options|
  options = attributes_and_options.extract_options!
  attributes = attributes_and_options

  options.assert_valid_keys(:for)
  suffix = options.fetch(:for)

  subject(:synchronized_attributes_by_suffix) do
    described_class.synchronized_attributes_by_suffix
  end

  context "for #{suffix}" do
    subject(:synchronized_attributes) do
      synchronized_attributes_by_suffix[suffix]
    end

    attributes.each do |attribute|
      it { should include(attribute) }
    end

    it 'should resolve all classes' do
      expect {
        described_class.synchronization_classes(for: suffix)
      }.not_to raise_error
    end
  end
end