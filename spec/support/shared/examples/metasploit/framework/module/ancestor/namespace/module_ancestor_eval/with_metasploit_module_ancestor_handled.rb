shared_examples_for 'Metasploit::Framework::Module::Ancestor::Namespace#module_ancestor_eval with Metasploit::Module::Module::Ancestor#handled?' do
  context 'handler_type_alias' do
    context 'with Exception' do
      before(:each) do
        File.open(module_ancestor.real_path, 'wb') do |f|
          f.puts 'module Metasploit4'
          # self.handler_type_alias not defined
          f.puts 'end'
        end
      end

      it 'should set #module_ancestor_eval_exception to exception raised by metasploit_module.handler_type_alias' do
        module_ancestor_eval

        namespace.module_ancestor_eval_exception.should be_a NoMethodError
      end

      it 'should not save module_ancestor' do
        expect {
          module_ancestor_eval
        }.to_not change {
          with_established_connection {
            Mdm::Module::Ancestor.count
          }
        }
      end

      it 'should make the namespace invalid' do
        namespace.should be_invalid
      end
    end

    context 'without Exception' do
      it 'should not set #module_ancestor_eval_exception' do
        namespace.module_ancestor_eval_exception.should be_nil
      end

      it 'should set module_ancestor.handler_type to metasploit_module.handler_type_alias' do
        expect {
          module_ancestor_eval
        }.to change(module_ancestor, :handler_type).to(@original_handler_type)
      end

      it_should_behave_like 'Metasploit::Framework::Module::Ancestor::Namespace#module_ancestor_eval true'
    end
  end
end
