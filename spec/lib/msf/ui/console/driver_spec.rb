require 'spec_helper'

describe Msf::Ui::Console::Driver do
  include_context 'Msf::Simple::Framework'

  subject(:driver) do
    described_class.new(
        prompt,
        prompt_char,
        opts
    )
  end

  let(:prompt) do
    described_class::DEFAULT_PROMPT
  end

  let(:prompt_char) do
    described_class::DEFAULT_PROMPT_CHAR
  end

  let(:opts) do
    {
        # turn off command pass through so tests don't have to worry about invoking system commands during tests
        'AllowCommandPassthru' => false,
        # disable banner because cmd_banner is not implemented
        'DisableBanner' => true,
        'Framework' => framework,
        # database already initialized by spec_helper
        'SkipDatabaseInit' => true
    }
  end

  it_should_behave_like 'Rex::Ui::Text::DispatcherShell' do
    let(:dispatcher_shell) do
      driver
    end
  end

  context '#metasploit_instance=' do
    include_context 'database cleaner'
    include_context 'metasploit_super_class_by_module_type'

    subject(:write_metasploit_instance) do
      driver.metasploit_instance = metasploit_instance
    end

    #
    # lets
    #

    let(:metasploit_class) do
      Class.new(metasploit_super_class)
    end

    let(:metasploit_instance) do
      metasploit_class.new
    end

    let(:module_class) do
      FactoryGirl.create(
          :mdm_module_class,
          module_type: module_type
      )
    end

    let(:module_type) do
      FactoryGirl.generate :metasploit_model_non_payload_module_type
    end

    #
    # Callbacks
    #

    before(:each) do
      stub_const('MetasploitClass', metasploit_class)
      metasploit_class.stub(module_class: module_class)
    end

    it 'restores the prompt' do
      expect(driver).to receive(:restore_prompt)

      write_metasploit_instance
    end

    context 'with #metasploit_instance' do
      let(:metasploit_instance_was) do
        Class.new(Msf::Module).new
      end

      #
      # Callbacks
      #

      before(:each) do
        driver.instance_variable_set :@metasploit_instance, metasploit_instance_was
      end

      it 'destacks dispatcher' do
        expect(driver).to receive(:destack_dispatcher)

        write_metasploit_instance
      end
    end

    context 'without #metasploit_instance' do
      it 'does not destack dispatcher' do
        expect(driver).not_to receive(:destack_dispatcher)

        write_metasploit_instance
      end
    end

    context 'with metasploit_instance' do
      it 'is the given metasploit_instance' do
        expect(write_metasploit_instance).to be metasploit_instance
      end

      it 'enstacks the module_type-specific dispatcher' do
        dispatcher_class = double('#metasploit_instance_dispatcher_class')
        expect(driver).to receive(:metasploit_instance_dispatcher_class).and_return(dispatcher_class)
        expect(driver).to receive(:enstack_dispatcher).with(dispatcher_class)

        write_metasploit_instance
      end

      it 'initializes the UI for the metasploit_instance' do
        expect(metasploit_instance).to receive(:init_ui).with(driver.input, driver.output)

        write_metasploit_instance
      end

      it 'replaces the prompt' do
        # intercept restore prompt as it uses update_prompt internally
        allow(driver).to receive(:restore_prompt)

        expect(driver).to receive(:update_prompt).with(an_instance_of(String), an_instance_of(String), true)

        write_metasploit_instance
      end

      context 'new prompt' do
        subject(:new_prompt) do
          driver.send(:prompt)
        end

        #
        # Callbacks
        #

        before(:each) do
          write_metasploit_instance
        end

        specify {
          # underline msf clear(formatting)
          expect(new_prompt).to start_with('%undmsf%clr')
        }

        it 'includes the module type' do
          expect(new_prompt).to include(metasploit_instance.module_type)
        end

        it "does not include the full name because it's too long" do
          expect(new_prompt).not_to include(metasploit_instance.full_name)
        end

        it 'includes the short name' do
          expect(new_prompt).to include(metasploit_instance.short_name)
        end
      end
    end

    context 'without metasploit_instance' do
      let(:metasploit_instance) do
        nil
      end

      it { should be_nil }
    end
  end

  context '#metapsloit_instance_dispatcher_class' do
    include_context 'metasploit_super_class_by_module_type'

    subject(:metasploit_instance_dispatcher_class) do
      driver.metasploit_instance_dispatcher_class
    end

    #
    # lets
    #

    let(:metasploit_class) do
      Class.new(metasploit_super_class)
    end

    let(:metasploit_instance) do
      metasploit_class.new
    end

    let(:module_type) do
      # have to exclude payloads because they require additional setup like handlers.
      FactoryGirl.generate :metasploit_model_non_payload_module_type
    end

    #
    # Callbacks
    #

    before(:each) do
      allow(driver).to receive(:metasploit_instance).and_return(metasploit_instance)
    end

    it 'calls module_type_dispatcher_class' do
      expect(described_class).to receive(:module_type_dispatcher_class).with(module_type)

      metasploit_instance_dispatcher_class
    end
  end

  context 'module_type_dispatcher_class' do
    subject(:module_type_dispatcher_class) do
      described_class.module_type_dispatcher_class(module_type)
    end

    context 'with auxiliary' do
      let(:module_type) do
        'auxiliary'
      end

      it { should be Msf::Ui::Console::CommandDispatcher::Auxiliary }
    end

    context 'with encoder' do
      let(:module_type) do
        'encoder'
      end

      it { should be Msf::Ui::Console::CommandDispatcher::Encoder }
    end

    context 'with exploit' do
      let(:module_type) do
        'exploit'
      end

      it { should be Msf::Ui::Console::CommandDispatcher::Exploit }
    end

    context 'with nop' do
      let(:module_type) do
        'nop'
      end

      it { should be Msf::Ui::Console::CommandDispatcher::Nop }
    end

    context 'with payload' do
      let(:module_type) do
        'payload'
      end

      it { should be Msf::Ui::Console::CommandDispatcher::Payload }
    end

    context 'with post' do
      let(:module_type) do
        'post'
      end

      it { should be Msf::Ui::Console::CommandDispatcher::Post }
    end
  end
end