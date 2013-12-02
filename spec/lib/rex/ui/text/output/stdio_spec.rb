require 'spec_helper'

describe Rex::Ui::Text::Output::Stdio do
  subject(:output) do
    described_class.new
  end

  it { should be_a Rex::Ui::Text::Output }

  context '#flush' do
    subject(:flush) do
      output.flush
    end

    it 'should flush $stdout' do
      $stdout.should_receive(:flush)

      flush
    end
  end

  context '#print_raw' do
    subject(:print_raw) do
      output.print_raw
    end

    context 'with message' do
      subject(:print_raw) do
        output.print_raw(message)
      end

      #
      # lets
      #

      let(:message) do
        'message'
      end

      #
      # callbacks
      #

      before(:each) do
        Rex::Compat.stub(is_windows: is_windows)
      end

      context 'with Windows' do
        #
        # lets
        #

        let(:is_windows) do
          true
        end

        #
        # callbacks
        #

        before(:each) do
          output.stub(supports_color?: supports_color)
        end

        context 'with #supports_color?' do
          let(:supports_color) do
            true
          end

          let(:windows_console_color_support) do
            double('WindowsConsoleColorSupport').tap { |windows_console_color_support|
              windows_console_color_support.should_receive(:write).with(message)
            }
          end

          it 'should create a WindowsConsoleColorSupport' do
            WindowsConsoleColorSupport.should_receive(:new).with($stdout).and_return(windows_console_color_support)

            print_raw
          end
        end

        context 'without #supports_color?' do
          let(:supports_color) do
            false
          end

          it 'should print to $stdout' do
            capture(:stdout) {

            }
          end
        end
      end

      context 'without Windows' do
        let(:is_windows) do
          false
        end

        it 'should print to $stdout' do
          $stdout.should_receive(:print).with(message)

          print_raw
        end
      end
    end

    context 'without message' do
      it 'should print empty string' do
        stdout = capture(:stdout) {
          print_raw
        }

        stdout.should be_empty
      end
    end
  end

  context '#supports_color?' do
    subject(:supports_color?) do
      output.supports_color?
    end

    before(:each) do
      output.config[:color] = color
    end

    context 'config[:color]' do
      context 'with false' do
        let(:color) do
          false
        end

        it { should be_false }
      end

      context 'with true' do
        let(:color) do
          true
        end

        it { should be_true }
      end

      context 'without false or true' do
        #
        # lets
        #

        let(:color) do
          nil
        end

        #
        # callbacks
        #

        before(:each) do
          Rex::Compat.stub(is_windows: windows)
        end

        context 'with Windows' do
          let(:windows) do
            true
          end

          it { should be_true }
        end

        context 'without Windows' do
          let(:windows) do
            false
          end

          around(:each) do |example|
            term_before = ENV.delete('TERM')

            begin
              example.run
            ensure
              ENV['TERM'] = term_before
            end
          end

          context 'with TERM' do
            before(:each) do
              ENV['TERM'] = term
            end

            context 'with linux' do
              let(:term) do
                'linux'
              end

              it { should be_true }
            end

            context 'with screen' do
              let(:term) do
                'screen'
              end

              it { should be_true }
            end

            context 'with rxvt' do
              let(:term) do
                'rxvt'
              end

              it { should be_true }
            end

            context 'with vt100' do
              let(:term) do
                'vt100'
              end

              it { should be_true }
            end

            context 'with vt103' do
              let(:term) do
                'vt103'
              end

              it { should be_true }
            end

            context 'with xterm' do
              let(:term) do
                'xterm'
              end

              it { should be_true }
            end

            context 'with xterm-color' do
              let(:term) do
                'xterm-color'
              end

              it { should be_true }
            end

            context 'with unknown value' do
              let(:term) do
                'unknown value'
              end

              it { should be_false }
            end
          end

          context 'without TERM' do
            it { should be_false }
          end
        end
      end
    end
  end

  context '#tty?' do
    subject(:tty?) do
      output.tty?
    end

    it 'should delegate to $stdout' do
      $stdout.should_receive(:tty?)

      tty?
    end
  end
end
