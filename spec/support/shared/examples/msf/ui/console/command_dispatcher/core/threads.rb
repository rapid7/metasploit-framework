shared_examples_for 'Msf::Ui::Console::CommandDispatcher::Core::Threads' do
  #
  # Shared context
  #

  shared_context 'named thread' do
    #
    # lets
    #

    let(:critical) do
      false
    end

    let(:name) do
      FactoryGirl.generate :metasploit_framework_thread_name
    end

    #
    # let!s
    #

    let!(:thread) do
      spawn(critical: false, name: name)
    end
  end

  #
  # methods
  #

  def spawn(options={})
    options.assert_valid_keys(:critical, :name)
    name = options.fetch(:name)
    critical = options[:critical] || false

    child_running = false

    thread = framework.threads.spawn(name, critical) {
      child_running = true
      Thread.stop
    }

    loop do
      if child_running
        break
      end
    end

    thread
  end

  context 'CONSTANTS' do
    context 'CMD_THREADS_OPTIONS' do
      subject(:cmd_threads_options) do
        described_class::CMD_THREADS_OPTIONS
      end

      context '-K' do
        subject(:k) do
          cmd_threads_options.fmt['-K']
        end

        context 'takes arguments' do
          subject(:takes_arguments) do
            k.first
          end

          it { should be_false }
        end

        context 'description' do
          subject(:description) do
            k.second
          end

          it { should == "Terminate all non-critical threads." }
        end
      end

      context '-h' do
        subject(:h) do
          cmd_threads_options.fmt['-h']
        end

        context 'takes arguments' do
          subject(:takes_arguments) do
            h.first
          end

          it { should be_false }
        end

        context 'description' do
          subject(:description) do
            h.second
          end

          it { should == "Help banner." }
        end
      end

      context '-i' do
        subject(:i) do
          cmd_threads_options.fmt['-i']
        end

        context 'takes arguments' do
          subject(:takes_arguments) do
            i.first
          end

          it { should be_true }
        end

        context 'description' do
          subject(:description) do
            i.second
          end

          it { should == "Lists detailed information about a thread." }
        end
      end

      context '-k' do
        subject(:k) do
          cmd_threads_options.fmt['-k']
        end

        context 'takes arguments' do
          subject(:takes_arguments) do
            k.first
          end

          it { should be_true }
        end

        context 'description' do
          subject(:description) do
            k.second
          end

          it { should == "Terminate the specified thread name." }
        end
      end

      context '-l' do
        subject(:l) do
          cmd_threads_options.fmt['-l']
        end

        context 'takes arguments' do
          subject(:takes_arguments) do
            l.first
          end

          it { should be_false }
        end

        context 'description' do
          subject(:description) do
            l.second
          end

          it { should == "List all background threads." }
        end
      end

      context '-v' do
        subject(:v) do
          cmd_threads_options.fmt['-v']
        end

        context 'takes arguments' do
          subject(:takes_arguments) do
            v.first
          end

          it { should be_false }
        end

        context 'description' do
          subject(:description) do
            v.second
          end

          it { should == "Print more detailed info.  Use with -i." }
        end
      end
    end
  end

  context '#cmd_threads' do
    subject(:cmd_threads) do
      core.cmd_threads(*arguments)
    end

    context 'with arguments' do
      context 'with -K' do
        let(:arguments) do
          ['-K']
        end

        it 'should call #cmd_threads_kill_all_non_critical' do
          core.should_receive(:cmd_threads_kill_all_non_critical).and_call_original

          cmd_threads
        end
      end

      context 'with -h' do
        let(:arguments) do
          ['-h']
        end

        it 'should call #cmd_threads_help' do
          core.should_receive(:cmd_threads_help).and_call_original

          cmd_threads
        end
      end

      context 'with -i' do
        let(:arguments) do
          ['-i', name]
        end

        let(:name) do
          'Thread Name'
        end

        context 'with -v' do
          let(:arguments) do
            super() + ['-v']
          end

          it 'should call #cmd_threads_info with verbose: true' do
            core.should_receive(:cmd_threads_info).with(
                name,
                hash_including(verbose: true)
            ).and_call_original

            cmd_threads
          end
        end

        context 'without -v' do
          it 'should call #cmd_threads_info with verbose: false' do
            core.should_receive(:cmd_threads_info).with(
                name,
                hash_including(verbose: false)
            ).and_call_original

            cmd_threads
          end
        end
      end

      context 'with -k' do
        let(:arguments) do
          ['-k', name]
        end

        let(:name) do
          'Thread Name'
        end

        it 'should call #cmd_threads_kill' do
          core.should_receive(:cmd_threads_kill).with(name, kind_of(Hash)).and_call_original

          cmd_threads
        end
      end

      context 'with -l' do
        let(:arguments) do
          ['-l']
        end

        it 'should call #cmd_threads_list' do
          core.should_receive(:cmd_threads_list).and_call_original

          cmd_threads
        end
      end
    end

    context 'without arguments' do
      let(:arguments) do
        []
      end

      it 'should run #cmd_threads_list' do
        core.should_receive(:cmd_threads_list).and_call_original

        cmd_threads
      end
    end
  end

  context '#cmd_threads_help' do
    subject(:cmd_threads_help) do
      core.cmd_threads_help
    end

    it 'should print option usage' do
      described_class::CMD_THREADS_OPTIONS.should_receive(:usage).and_call_original

      cmd_threads_help
    end
  end

  context '#cmd_threads_tabs' do
    #
    #
    # Shared
    #
    #

    #
    # contexts
    #


    #
    # examples
    #

    shared_examples_for 'all options' do
      it 'should return all options' do
        expect(cmd_threads_tabs).to match_array(
            [
                '-K',
                '-h',
                '-i',
                '-k',
                '-l',
                '-v'
            ]
                                   )
      end
    end

    subject(:cmd_threads_tabs) do
      core.cmd_threads_tabs(partial_word, words)
    end

    let(:partial_word) do
      ''
    end

    context 'with words' do
      context 'with -K' do
        let(:words) do
          ['-K']
        end

        it 'should include all options except -K' do
          expect(cmd_threads_tabs).to match_array(
              [
                  '-h',
                  '-i',
                  '-k',
                  '-l',
                  '-v'
              ]
                                      )
        end
      end

      context 'with -h' do
        let(:words) do
          ['-h']
        end

        it 'should include all options except -h' do
          expect(cmd_threads_tabs).to match_array(
              [
                  '-K',
                  '-i',
                  '-k',
                  '-l',
                  '-v'
              ]
                                      )
        end
      end

      context 'with -i' do
        include_context 'named thread'

        let(:words) do
          ['-i']
        end

        it 'should return thread names' do
          expect(cmd_threads_tabs).to match_array(
                                          [
                                              name
                                          ]
                                      )
        end

        context 'with thread name' do
          let(:words) do
            super() + [name]
          end

          it_should_behave_like 'all options'
        end
      end

      context 'with -k' do
        include_context 'named thread'

        let(:words) do
          ['-k']
        end

        it 'should return thread names' do
          expect(cmd_threads_tabs).to match_array(
                                          [
                                              thread[:metasploit_framework_thread].name
                                          ]
                                      )
        end

        context 'with thread name' do
          let(:words) do
            super() + [name]
          end

          it_should_behave_like 'all options'
        end
      end

      context 'with -l' do
        let(:words) do
          ['-l']
        end

        it_should_behave_like 'all options'
      end

      context 'with -v' do
        let(:words) do
          ['-v']
        end

        it 'should include all options except -v' do
          expect(cmd_threads_tabs).to match_array(
              [
                  '-K',
                  '-h',
                  '-i',
                  '-k',
                  '-l'
              ]
                                      )
        end
      end
    end

    context 'without words' do
      let(:words) do
        []
      end

      it_should_behave_like 'all options'
    end
  end

  context '#cmd_threads_info' do
    subject(:cmd_threads_info) do
      core.send(:cmd_threads_info, name, options)
    end

    let(:name) do
      FactoryGirl.generate :metasploit_framework_thread_name
    end

    let(:options) do
      {}
    end

    let(:output) do
      capture(:stdout) {
        cmd_threads_info
      }
    end

    it 'should use #cmd_threads_with_thread_named' do
      core.should_receive(:cmd_threads_with_thread_named).with(name)

      cmd_threads_info
    end

    context 'with thread' do
      include_context 'named thread'

      it 'should include name' do
        output.should include "Name:     #{name}"
      end

      it 'should include status' do
        output.should include "Status:   #{thread.status}"
      end

      it 'should include criticality' do
        output.should include "Critical: False"
      end

      it 'should include spawn time' do
        output.should include "Spawned:  #{thread[:metasploit_framework_thread].spawned_at}"
      end

      context 'with verbose: false' do
        let(:options) do
          {
              verbose: false
          }
        end

        it 'should not include Thread Source section' do
          output.should_not include 'Thread Source'
        end
      end

      context 'with verbose: true' do
        let(:options) do
          {
              verbose: true
          }
        end

        it 'should include Thread Source section' do
          output.should include 'Thread Source'
        end

        it 'should include backtrace' do
          metasploit_framework_thread = thread[:metasploit_framework_thread]

          metasploit_framework_thread.backtrace.each do |line|
            # prefix for indenting under section
            output.should include "  #{line}"
          end
        end

      end
    end

    context 'without thread' do
      it 'should print Invalid Thread Name' do
        output.should include 'Invalid Thread Name'
      end
    end
  end

  context '#cmd_threads_kill' do
    subject(:cmd_threads_kill) do
      core.send(:cmd_threads_kill, name)
    end

    let(:name) do
      FactoryGirl.generate :metasploit_framework_thread_name
    end

    it 'should use #cmd_threads_with_thread_named' do
      core.should_receive(:cmd_threads_with_thread_named).with(name)

      cmd_threads_kill
    end

    context 'with thread' do
      include_context 'named thread'

      it 'should call #cmd_threads_kill_thread' do
        core.should_receive(:cmd_threads_kill_thread).with(thread)

        cmd_threads_kill
      end
    end

    context 'without thread' do
      it 'should print Invalid Thread Name' do
        stdout  = capture(:stdout) {
          cmd_threads_kill
        }

        stdout.should include 'Invalid Thread Name'
      end
    end
  end

  context '#cmd_threads_kill_all_non_critical' do
    subject(:cmd_threads_kill_all_non_critical) do
      core.send(:cmd_threads_kill_all_non_critical)
    end

    #
    # lets
    #

    let(:critical_thread_name) do
      FactoryGirl.generate :metasploit_framework_thread_name
    end

    let(:non_critical_thread_name) do
      FactoryGirl.generate :metasploit_framework_thread_name
    end

    #
    # let!s
    #

    let!(:critical_thread) do
      spawn(
          critical: true,
          name: critical_thread_name
      )
    end

    let!(:non_critical_thread) do
      spawn(
          critical: false,
          name: non_critical_thread_name
      )
    end

    it 'should not kill critical threads' do
      cmd_threads_kill_all_non_critical

      critical_thread.should be_alive
    end

    it 'should kill non-critical threads' do
      non_critical_thread.should_receive(:kill).at_least(:twice).and_call_original

      cmd_threads_kill_all_non_critical
    end

    it 'should call #cmd_threads_kill_thread' do
      core.should_receive(:cmd_threads_kill_thread).with(non_critical_thread)

      cmd_threads_kill_all_non_critical
    end
  end

  context '#cmd_threads_kill_thread' do
    include_context 'named thread'

    subject(:cmd_threads_kill_thread) do
      core.send(:cmd_threads_kill_thread, thread)
    end

    it 'should print thread name' do
      stdout = capture(:stdout) {
        cmd_threads_kill_thread
      }

      stdout.should include "Terminating thread: #{name}..."
    end

    it 'should kill the thread' do
      # if test completes before thread is completely destroyed, then the thread cleaner may call kill a thread time
      thread.should_receive(:kill).at_least(:twice).and_call_original

      cmd_threads_kill_thread
    end
  end

  context '#cmd_threads_list' do
    include_context 'named thread'

    subject(:cmd_threads_list) do
      core.send(:cmd_threads_list)
    end

    let(:output) do
      capture(:stdout) {
        cmd_threads_list
      }
    end

    it 'should include name' do
      output.should include name
    end

    it 'should include status' do
      output.should include thread.status
    end

    it 'should include criticality' do
      output.should include 'False'
    end

    it 'should include spawn time' do
      output.should include thread[:metasploit_framework_thread].spawned_at.to_s
    end
  end
end