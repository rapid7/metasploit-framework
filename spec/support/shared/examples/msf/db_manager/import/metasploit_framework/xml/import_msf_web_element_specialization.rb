# -*- coding:binary -*-
RSpec.shared_examples_for 'Msf::DBManager::Import::MetasploitFramework::XML#import_msf_web_element specialization' do
  it 'should call #import_msf_web_element with element' do
    expect(db_manager).to receive(:import_msf_web_element).with(element, anything)

    subject
  end

  it 'should call #import_msf_web_element with :allow_yaml and :workspace' do
    expect(db_manager).to receive(:import_msf_web_element).with(
        anything,
        hash_including(
            :allow_yaml => allow_yaml,
            :workspace => workspace
        )
    )

    subject
  end

  it 'should call #import_msf_web_element with :type' do
    expect(db_manager).to receive(:import_msf_web_element).with(
        anything,
        hash_including(
            :type => type
        )
    )

    subject
  end

  it 'should pass block to #import_msf_web_element as :notifier' do
    expect(db_manager).to receive(
        :import_msf_web_element
    ).with(
        anything,
        hash_including(:notifier => notifier)
    )

    subject
  end
end
