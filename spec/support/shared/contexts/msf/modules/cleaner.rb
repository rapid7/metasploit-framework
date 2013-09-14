shared_context 'Msf::Modules Cleaner' do
  def remove_msf_modules_constants
    begin
      namespace = Msf::Modules
    rescue NameError
      # ignored
    else
      inherit = false

      direct_constants = namespace.constants(inherit)

      direct_constants.each do |constant|
        namespace.send(:remove_const, constant)
      end
    end
  end

  before(:all) do
    remove_msf_modules_constants
  end

  after(:each) do
    remove_msf_modules_constants
  end
end