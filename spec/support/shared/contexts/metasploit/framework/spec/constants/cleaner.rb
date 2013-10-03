shared_context 'Metasploit::Framework::Spec::Constants cleaner' do |options={}|
  options.assert_valid_keys(:after)

  scope = options.fetch(:after, :each)

  def remove_msf_modules_constants
    Metasploit::Framework::Spec::Constants.each do |parent_constant, child_name|
      parent_constant.send(:remove_const, child_name)
    end
  end

  before(:all) do
    remove_msf_modules_constants
  end

  after(scope) do
    remove_msf_modules_constants
  end
end