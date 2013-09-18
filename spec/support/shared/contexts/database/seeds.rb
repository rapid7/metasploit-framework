shared_context 'database seeds' do |options={}|
  options.assert_valid_keys(:scope)

  scope = options.fetch(:scope, :each)

  include_context 'database cleaner', after: scope

  before(scope) do
    with_established_connection do
      load Metasploit::Framework.root.join('db', 'seeds.rb')
    end
  end
end