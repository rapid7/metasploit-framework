shared_examples_for 'Metasploit::Framework::Module::Cache#prefetch real_path' do |real_path, options={}|
  options.assert_valid_keys(:module_classes)

  module_classes_matcher = options.fetch(:module_classes)

  real_pathname = Pathname.new(real_path)
  relative_pathname = real_pathname.relative_path_from(Metasploit::Framework.root)

  # have context be path relative to project root so context name is consistent no matter where the specs run
  context "#{relative_pathname}" do
    context 'Mdm::Module::Ancestor' do
      subject(:module_ancestor) do
        with_established_connection {
          @module_path.module_ancestors.where(real_path: real_path).first
        }
      end

      it { should_not be_nil }

      context 'Mdm::Module::Classes' do
        subject(:module_classes) do
          module_ancestor.descendants
        end

        # can't give description because want the one from the module_classes_matcher
        specify {
          with_established_connection {
            module_classes.should send(module_classes_matcher, 1).items
          }
        }

        it 'should each have Mdm::Module::Instance' do
          with_established_connection do
            module_classes.each do |module_class|
              module_class.module_instance.should_not be_nil
            end
          end
        end
      end
    end
  end
end