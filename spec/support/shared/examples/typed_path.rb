# -*- coding:binary -*-
RSpec.shared_examples_for 'typed_path' do |map|
  map ||= {}
  if map.length < 1
    raise ArgumentError,
          "type_path shared example requires a hash mapping the type constant name to the directory name: " \
           "it_should_behave_like 'type_path', 'Msf::Auxiliary' => 'auxiliary'"
  end

  if map.length > 1
    raise ArgumentError,
          "only one constant to directory mapping should be passed to each shared example, not #{map.length}"
  end

  type_constant_name, directory = map.shift

  context "with #{type_constant_name} type" do
    let(:type_constant) do
      type_constant_name.constantize
    end

    it "should start with #{directory} directory" do
      typed_path = described_class.typed_path(type_constant, module_reference_name)
      first_directory = typed_path.split(File::SEPARATOR).first

      expect(first_directory).to eq directory
    end
  end
end
