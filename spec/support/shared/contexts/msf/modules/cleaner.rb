shared_context 'Msf::Modules Cleaner' do |options={}|
  options.assert_valid_keys(:after)

  scope = options.fetch(:after, :each)

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

  after(scope) do
    remove_msf_modules_constants
  end
end