# -*- coding:binary -*-

require 'spec_helper'

RSpec.describe Rex::Ui::Interactive do
  let(:interactive_class) do
    Class.new do
      include Rex::Ui::Interactive

      attr_reader :remote_writes
      attr_accessor :remote_fd

      def initialize
        @remote_writes = []
      end

      def _remote_fd(_stream)
        remote_fd
      end

      def _readline_read_remote(_stream)
        remote_fd.read_nonblock(Rex::Ui::Interactive::READLINE_SHORT_READ)
      end

      def _readline_write_remote(_stream, line)
        remote_writes << line
      end
    end
  end

  let(:printed) { +'' }
  let(:output) do
    instance_double(Rex::Ui::Text::Output::Stdio).tap do |output|
      allow(output).to receive(:print) { |msg| printed << msg }
      allow(output).to receive(:prompting?).and_return(false)
    end
  end
  let(:input_fd) { instance_double(IO, tty?: true) }
  let(:input) do
    instance_double(Rex::Ui::Text::Input::Readline, fd: input_fd).tap do |input|
      prompt = 'msf > '
      allow(input).to receive(:prompt) { prompt }
      allow(input).to receive(:prompt=) { |value| prompt = value }
    end
  end

  subject(:interactive) do
    interactive_class.new.tap do |interactive|
      interactive.user_input = input
      interactive.user_output = output
      interactive.interacting = true
    end
  end

  describe '#interact_with_readline?' do
    before(:each) do
      stub_const('RbReadline', Module.new)
      allow(input).to receive(:is_a?).with(Rex::Ui::Text::Input::Readline).and_return(true)
      allow(Rex::Compat).to receive(:is_windows).and_return(false)
    end

    it 'is true for rb-readline input on a terminal' do
      expect(interactive.send(:interact_with_readline?)).to be_truthy
    end

    it 'is false for other inputs that support pgets' do
      interactive.user_input = Rex::Ui::Text::Input::Stdio.new.extend(Rex::Ui::Text::Shell::InputShell)
      expect(interactive.send(:interact_with_readline?)).to be_falsey
    end

    it 'is false when the input is not a terminal' do
      allow(input_fd).to receive(:tty?).and_return(false)
      expect(interactive.send(:interact_with_readline?)).to be_falsey
    end

    it 'is false without rb-readline' do
      hide_const('RbReadline')
      expect(interactive.send(:interact_with_readline?)).to be_falsey
    end

    it 'is false on Windows, where the line being edited cannot be redrawn' do
      allow(Rex::Compat).to receive(:is_windows).and_return(true)
      expect(interactive.send(:interact_with_readline?)).to be_falsey
    end
  end

  describe '#readline_prompt' do
    it 'leaves plain text unchanged' do
      expect(interactive.send(:readline_prompt, 'user@host:~$ ')).to eq('user@host:~$ ')
    end

    it 'marks colour sequences as non-printing' do
      prompt = "\e[01;32muser@host\e[00m:~$ "
      expect(interactive.send(:readline_prompt, prompt)).to eq("\x01\e[01;32m\x02user@host\x01\e[00m\x02:~$ ")
    end

    it 'marks window title sequences as non-printing' do
      prompt = "\e]0;user@host: ~\auser@host:~$ "
      expect(interactive.send(:readline_prompt, prompt)).to eq("\x01\e]0;user@host: ~\a\x02user@host:~$ ")
    end

    it 'only keeps the text after the last carriage return' do
      expect(interactive.send(:readline_prompt, "progress 50%\rprogress 100%")).to eq('progress 100%')
    end
  end

  describe '#readline_print_remote' do
    before(:each) do
      interactive.instance_variable_set(:@readline_pending, '')
    end

    it 'prints complete lines and uses the rest as the prompt' do
      interactive.send(:readline_print_remote, "uid=0(root)\nroot@host:~# ", input, output, false)

      expect(printed).to eq("uid=0(root)\n")
      expect(input.prompt).to eq('root@host:~# ')
    end

    it 'keeps an incomplete line until the rest of it arrives' do
      interactive.send(:readline_print_remote, 'hello ', input, output, false)
      expect(printed).to eq('')

      interactive.send(:readline_print_remote, "world\n$ ", input, output, false)
      expect(printed).to eq("hello world\n")
      expect(input.prompt).to eq('$ ')
    end

    it 'prints screen control sequences instead of keeping them in the prompt' do
      interactive.send(:readline_print_remote, "\e[H\e[2J$ ", input, output, false)

      expect(printed).to eq("\e[H\e[2J")
      expect(input.prompt).to eq('$ ')
    end

    it 'prints a long line without a newline as it arrives' do
      long_line = 'A' * (Rex::Ui::Interactive::READLINE_PROMPT_MAX + 1)
      interactive.send(:readline_print_remote, long_line, input, output, false)

      expect(printed).to eq(long_line)
      expect(input.prompt).to eq('')
    end

    it 'does not break a long line that arrives in several reads' do
      long_line = 'A' * (Rex::Ui::Interactive::READLINE_PROMPT_MAX + 1)
      interactive.send(:readline_print_remote, long_line, input, output, false)
      interactive.send(:readline_print_remote, 'BBB', input, output, false)
      interactive.send(:readline_print_remote, "CCC\n$ ", input, output, false)

      expect(printed).to eq("#{long_line}BBBCCC\n")
      expect(input.prompt).to eq('$ ')
    end

    it 'wipes every row of the line being edited before printing' do
      rb_readline = stub_const('RbReadline', spy('RbReadline'))

      interactive.send(:readline_print_remote, "arrived\n$ ", input, output, true)

      expect(rb_readline).to have_received(:_rl_move_vert).with(0)
      expect(printed).to eq("\r\e[Jarrived\n")
    end

    it 'redraws the line being edited once while a long line is printed' do
      rb_readline = stub_const('RbReadline', spy('RbReadline'))
      long_line = 'A' * (Rex::Ui::Interactive::READLINE_PROMPT_MAX + 1)

      interactive.send(:readline_print_remote, long_line, input, output, true)
      interactive.send(:readline_print_remote, long_line, input, output, true)

      expect(rb_readline).to have_received(:rl_forced_update_display).once
    end
  end

  describe '#interact_readline' do
    let(:pipe) { IO.pipe }
    let(:rb_readline) do
      Module.new do
        const_set(:RL_STATE_READCMD, 8)

        def self.rl_event_hook
          :previous_hook
        end

        def self.rl_isstate(_state)
          true
        end

        def self.rl_event_hook=(_hook); end

        def self._rl_move_vert(_row); end

        def self.rl_set_prompt(_prompt); end

        def self.rl_forced_update_display; end

        def self.keymap
          @keymap ||= { "\t" => :rl_complete }
        end

        def self.rl_function_of_keyseq(keyseq, _map, _type)
          keymap[keyseq]
        end

        def self.rl_bind_key(key, function)
          keymap[key] = function
        end
      end
    end

    before(:each) do
      interactive.remote_fd = pipe.first
      stub_const('RbReadline', rb_readline)
      allow(rb_readline).to receive(:rl_event_hook=)
      allow(Signal).to receive(:trap).and_call_original
      allow(Signal).to receive(:trap).with('TSTP').and_return('DEFAULT')
      allow(Signal).to receive(:trap).with('TSTP', 'DEFAULT')
    end

    after(:each) do
      pipe.each(&:close)
    end

    # Answers pgets with each of the lines in turn and stops interacting once
    # the last one has been read
    def type_lines(*lines)
      allow(input).to receive(:pgets) do
        interactive.interacting = false if lines.size == 1
        lines.shift
      end
    end

    it 'sends each line without the trailing newline' do
      type_lines("id\n", 'whoami')

      interactive.send(:interact_readline, nil)

      expect(interactive.remote_writes).to eq(%w[id whoami])
    end

    it 'sends an empty line for Ctrl+D' do
      type_lines(nil, 'exit')

      interactive.send(:interact_readline, nil)

      expect(interactive.remote_writes).to eq(['', 'exit'])
    end

    it 'restores the previous prompt' do
      type_lines('exit')

      interactive.send(:interact_readline, nil)

      expect(input.prompt).to eq('msf > ')
    end

    it 'restores the previous readline event hook' do
      type_lines('exit')

      interactive.send(:interact_readline, nil)

      expect(rb_readline).to have_received(:rl_event_hook=).with(:previous_hook)
    end

    it 'sends Tab to the remote side instead of completing console commands' do
      tab_while_typing = nil
      allow(input).to receive(:pgets) do
        tab_while_typing = rb_readline.keymap["\t"]
        interactive.interacting = false
        'id'
      end

      interactive.send(:interact_readline, nil)

      expect([tab_while_typing, rb_readline.keymap["\t"]]).to eq(%i[rl_tab_insert rl_complete])
    end

    it 'prints output that arrives while no line is being read straight away' do
      allow(input).to receive(:pgets).and_return('id')
      allow(interactive).to receive(:_readline_write_remote) do
        pipe.last.write("uid=0(root)\n$ ")
        sleep(0.01) until printed.include?("\n")
        interactive.interacting = false
      end

      Timeout.timeout(5) { interactive.send(:interact_readline, nil) }

      expect(printed).to eq("uid=0(root)\n")
    end

    it 'holds output that arrives while typing until readline is between key presses' do
      printed_while_typing = nil
      allow(input).to receive(:pgets) do
        pipe.last.write("hello\n$ ")
        sleep(0.01) until interactive.instance_variable_get(:@readline_queue).any?
        printed_while_typing = printed.dup
        # What rb-readline does between key presses
        rb_readline.send(Rex::Ui::Interactive::READLINE_EVENT_HOOK)
        interactive.interacting = false
        'id'
      end

      Timeout.timeout(5) { interactive.send(:interact_readline, nil) }

      expect([printed_while_typing, printed]).to eq(['', "\r\e[Jhello\n"])
    end

    it 'asks to background the session when Ctrl+Z is pressed' do
      allow(input).to receive(:pgets).and_raise(Rex::Ui::Interactive::ReadlineSuspend)
      # Answering yes stops interacting
      allow(interactive).to receive(:_suspend) { interactive.interacting = false }

      Timeout.timeout(5) { interactive.send(:interact_readline, nil) }

      expect(interactive).to have_received(:_suspend).once
      expect(interactive.remote_writes).to be_empty
    end

    it 'ignores Ctrl+Z while asking whether to background the session' do
      tstp = nil
      allow(Signal).to receive(:trap).with('TSTP') do |&handler|
        tstp = handler
        'DEFAULT'
      end
      allow(input).to receive(:pgets) { tstp.call }
      allow(interactive).to receive(:_suspend) do
        tstp.call
        interactive.interacting = false
      end

      expect { Timeout.timeout(5) { interactive.send(:interact_readline, nil) } }.not_to raise_error
      expect(interactive).to have_received(:_suspend).once
    end

    it 'prints the last output before noticing that the remote side closed' do
      allow(input).to receive(:pgets) do
        pipe.last.write("logout\n")
        pipe.last.close
        sleep(0.01) until interactive.instance_variable_get(:@readline_queue).any?
        # What rb-readline does between key presses
        rb_readline.send(Rex::Ui::Interactive::READLINE_EVENT_HOOK)
        sleep(5)
      end

      expect { Timeout.timeout(5) { interactive.send(:interact_readline, nil) } }.to raise_error(EOFError)
      expect(printed).to eq("\r\e[Jlogout\n")
    end

    it 'keeps reading without waiting for the event hook while more output is on its way' do
      allow(input).to receive(:pgets) do
        pipe.last.write('A' * Rex::Ui::Interactive::READLINE_SHORT_READ)
        sleep(0.01) until interactive.instance_variable_get(:@readline_queue).any?
        pipe.last.write("\n$ ")
        sleep(0.01) until interactive.instance_variable_get(:@readline_queue).size == 2
        interactive.interacting = false
        'id'
      end

      Timeout.timeout(5) { interactive.send(:interact_readline, nil) }

      expect(printed).to eq("#{'A' * Rex::Ui::Interactive::READLINE_SHORT_READ}\n")
    end

    it 'prints output still queued when interrupted in place of the line being edited' do
      allow(input).to receive(:pgets) do
        pipe.last.write("bye\n")
        sleep(0.01) until interactive.instance_variable_get(:@readline_queue).any?
        raise Interrupt
      end

      expect { Timeout.timeout(5) { interactive.send(:interact_readline, nil) } }.to raise_error(Interrupt)
      expect(printed).to eq("\r\e[Jbye\n")
    end

    it 'raises EOFError when the remote side closes' do
      allow(input).to receive(:pgets) do
        pipe.last.close
        sleep(5)
      end

      expect { Timeout.timeout(5) { interactive.send(:interact_readline, nil) } }.to raise_error(EOFError)
      expect(input.prompt).to eq('msf > ')
    end
  end
end
