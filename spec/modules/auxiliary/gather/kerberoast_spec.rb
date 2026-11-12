require 'rspec'

RSpec.describe 'Kerberoast SPN selection' do
  include_context 'Msf::Simple::Framework#modules loading'

  let(:subject) do
    load_and_create_module(
      module_type: 'auxiliary',
      reference_name: 'gather/kerberoast'
    )
  end

  let(:ldap) { double('ldap') }
  let(:roasted) { [] }

  def ldap_result(username, spns)
    double("ldap result #{username}", samaccountname: [username], serviceprincipalname: spns)
  end

  def stub_ldap_results(*results)
    expectation = allow(subject).to receive(:run_builtin_ldap_query)
                  .with('ENUM_USER_SPNS_KERBEROAST', ldap: ldap)
    results.each { |result| expectation = expectation.and_yield(result) }
  end

  before(:each) do
    allow(subject).to receive(:verify_options)
    allow(subject).to receive(:ldap_connect).and_yield(ldap)
    allow(subject).to receive(:validate_bind_success!)
    allow(subject).to receive(:adds_get_domain_info).and_return({ dns_name: 'corp.local' })
    allow(subject).to receive(:report_hash)
    allow(subject).to receive(:print_status)
    allow(subject).to receive(:print_good)
    allow(subject).to receive(:print_error)
    allow(subject).to receive(:print_warning)
    allow(Metasploit::Framework::Hashes).to receive(:identify_hash).and_return('krb5tgs-rc4')
    allow(subject).to receive(:roast) do |username, spn, **_opts|
      roasted << [username, spn]
      "$krb5tgs$23$*#{username}$corp.local$#{spn}*$deadbeef"
    end
  end

  describe '#run_ldap' do
    context 'when the first SPN is malformed and a later SPN is valid' do
      it 'requests a ticket using the valid SPN' do
        stub_ldap_results(ldap_result('svc_a', ['bad/host.corp.local/corp.local', 'MSSQLSvc/db01']))

        subject.run_ldap

        expect(roasted).to eq([['svc_a', 'MSSQLSvc/db01']])
        expect(subject).not_to have_received(:print_warning)
      end
    end

    context 'when an account has no valid SPNs' do
      it 'warns, skips the account and keeps enumerating' do
        stub_ldap_results(
          ldap_result('svc_bad', ['bad/a/b', 'also/bad/c']),
          ldap_result('svc_good', ['HTTP/web01'])
        )

        subject.run_ldap

        expect(subject).to have_received(:print_warning).with(/Ignoring invalid SPN for svc_bad/).once
        expect(roasted).to eq([['svc_good', 'HTTP/web01']])
      end
    end

    context 'when the first SPN is valid' do
      it 'uses the first SPN as before' do
        stub_ldap_results(ldap_result('svc_c', ['HTTP/web01', 'MSSQLSvc/db01']))

        subject.run_ldap

        expect(roasted).to eq([['svc_c', 'HTTP/web01']])
      end
    end
  end
end
