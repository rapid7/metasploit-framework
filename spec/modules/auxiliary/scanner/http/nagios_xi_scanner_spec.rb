require 'rspec'

RSpec.describe 'Nagios XI Scanner' do
  include_context 'Msf::Simple::Framework#modules loading'

  subject(:mod) do
    load_and_create_module(
      module_type: 'auxiliary',
      reference_name: 'scanner/http/nagios_xi_scanner'
    )
  end

  let(:host) { '192.0.2.1' }

  before do
    mod.datastore['RHOST'] = host
    mod.datastore['RPORT'] = 80
    mod.datastore['USERNAME'] = 'nagiosadmin'
    mod.datastore['PASSWORD'] = 'password'
    mod.datastore['VERSION'] = nil

    allow(mod).to receive(:send_request_cgi) do
      raise 'Unexpected HTTP request'
    end
  end

  describe '#run_host' do
    it 'uses the named message when the initial login fails' do
      mod.datastore['FINISH_INSTALL'] = false

      allow(mod).to receive(:nagios_xi_login)
        .with('nagiosadmin', 'password', false)
        .and_return({ status: 2, message: 'authentication failed' })

      expect(mod).to receive(:print_error)
        .with(a_string_ending_with(' - authentication failed'))

      mod.run_host(host)
    end

    it 'uses the named message when the post-install retry login fails' do
      mod.datastore['FINISH_INSTALL'] = true

      allow(mod).to receive(:nagios_xi_login)
        .with('nagiosadmin', 'password', true)
        .and_return({ status: 4, message: nil })
      allow(mod).to receive(:install_nagios_xi)
        .with('password')
        .and_return(nil)
      allow(mod).to receive(:login_after_install_or_license)
        .with('nagiosadmin', 'password', true)
        .and_return({ status: 2, message: 'retry failed' })

      expect(mod).to receive(:print_error)
        .with(a_string_ending_with(' - retry failed'))

      mod.run_host(host)
    end

    it 'reads named auth_cookies and nsp on the unsigned-license branch' do
      mod.datastore['FINISH_INSTALL'] = true

      allow(mod).to receive(:nagios_xi_login)
        .with('nagiosadmin', 'password', true)
        .and_return(
          {
            status: 5,
            auth_cookies: 'nagiosxi=abc;',
            nsp: 'nsp_token'
          }
        )
      allow(mod).to receive(:print_error)

      expect(mod).to receive(:sign_license_agreement)
        .with('nagiosxi=abc;', 'nsp_token')
        .and_return([2, 'signing failed'])

      mod.run_host(host)
    end

    it 'uses the named message when the post-license retry login fails' do
      mod.datastore['FINISH_INSTALL'] = true

      allow(mod).to receive(:nagios_xi_login)
        .with('nagiosadmin', 'password', true)
        .and_return(
          {
            status: 5,
            auth_cookies: 'nagiosxi=abc;',
            nsp: 'nsp_token'
          }
        )
      allow(mod).to receive(:sign_license_agreement)
        .and_return(nil)
      allow(mod).to receive(:login_after_install_or_license)
        .with('nagiosadmin', 'password', true)
        .and_return({ status: 2, message: 'retry failed' })

      expect(mod).to receive(:print_error)
        .with(a_string_ending_with(' - retry failed'))

      mod.run_host(host)
    end

    it 'passes the named dashboard body to nagios_xi_version on success' do
      mod.datastore['FINISH_INSTALL'] = false

      allow(mod).to receive(:nagios_xi_login)
        .with('nagiosadmin', 'password', false)
        .and_return(
          {
            status: 0,
            body: 'dashboard body',
            auth_cookies: 'nagiosxi=abc;'
          }
        )
      allow(mod).to receive(:print_good)
      allow(mod).to receive(:print_status)
      allow(mod).to receive(:rce_check)

      expect(mod).to receive(:nagios_xi_version)
        .with('dashboard body')
        .and_return('5.11.1')

      mod.run_host(host)
    end
  end
end
