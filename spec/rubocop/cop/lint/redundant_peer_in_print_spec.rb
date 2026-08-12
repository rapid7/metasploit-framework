# frozen_string_literal: true

require 'rubocop/cop/lint/redundant_peer_in_print'
require 'rubocop/rspec/support'

RSpec.describe RuboCop::Cop::Lint::RedundantPeerInPrint, :config do
  subject(:cop) { described_class.new(config) }

  let(:config) { RuboCop::Config.new }

  context 'when message starts with #{peer}' do
    it 'registers an offense for print_status with peer prefix and separator' do
      expect_offense(<<~RUBY)
        print_status("\#{peer} - Starting scan")
        ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ Lint/RedundantPeerInPrint: Redundant peer/host prefix in print message. The framework auto-prepends host:port via `print_prefix` -- see CONTRIBUTING.md.
      RUBY

      expect_correction(<<~RUBY)
        print_status("Starting scan")
      RUBY
    end

    it 'registers an offense for print_error with peer prefix and space only' do
      expect_offense(<<~RUBY)
        print_error("\#{peer} Connection failed")
        ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ Lint/RedundantPeerInPrint: Redundant peer/host prefix in print message. The framework auto-prepends host:port via `print_prefix` -- see CONTRIBUTING.md.
      RUBY

      expect_correction(<<~RUBY)
        print_error("Connection failed")
      RUBY
    end

    it 'registers an offense for print_good with peer prefix' do
      expect_offense(<<~RUBY)
        print_good("\#{peer} - Login successful")
        ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ Lint/RedundantPeerInPrint: Redundant peer/host prefix in print message. The framework auto-prepends host:port via `print_prefix` -- see CONTRIBUTING.md.
      RUBY

      expect_correction(<<~RUBY)
        print_good("Login successful")
      RUBY
    end

    it 'registers an offense for vprint_status with peer prefix' do
      expect_offense(<<~RUBY)
        vprint_status("\#{peer} - Verbose message")
        ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ Lint/RedundantPeerInPrint: Redundant peer/host prefix in print message. The framework auto-prepends host:port via `print_prefix` -- see CONTRIBUTING.md.
      RUBY

      expect_correction(<<~RUBY)
        vprint_status("Verbose message")
      RUBY
    end

    it 'registers an offense for vprint_error with peer prefix' do
      expect_offense(<<~RUBY)
        vprint_error("\#{peer} - Error occurred")
        ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ Lint/RedundantPeerInPrint: Redundant peer/host prefix in print message. The framework auto-prepends host:port via `print_prefix` -- see CONTRIBUTING.md.
      RUBY

      expect_correction(<<~RUBY)
        vprint_error("Error occurred")
      RUBY
    end

    it 'registers an offense for print_warning with peer prefix' do
      expect_offense(<<~RUBY)
        print_warning("\#{peer} - Something wrong")
        ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ Lint/RedundantPeerInPrint: Redundant peer/host prefix in print message. The framework auto-prepends host:port via `print_prefix` -- see CONTRIBUTING.md.
      RUBY

      expect_correction(<<~RUBY)
        print_warning("Something wrong")
      RUBY
    end

    it 'registers an offense for print_bad with peer prefix' do
      expect_offense(<<~RUBY)
        print_bad("\#{peer} - Bad thing")
        ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ Lint/RedundantPeerInPrint: Redundant peer/host prefix in print message. The framework auto-prepends host:port via `print_prefix` -- see CONTRIBUTING.md.
      RUBY

      expect_correction(<<~RUBY)
        print_bad("Bad thing")
      RUBY
    end
  end

  context 'when message starts with #{rhost}:#{rport}' do
    it 'registers an offense and corrects print_status' do
      expect_offense(<<~RUBY)
        print_status("\#{rhost}:\#{rport} - Sending request")
        ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ Lint/RedundantPeerInPrint: Redundant peer/host prefix in print message. The framework auto-prepends host:port via `print_prefix` -- see CONTRIBUTING.md.
      RUBY

      expect_correction(<<~RUBY)
        print_status("Sending request")
      RUBY
    end

    it 'registers an offense and corrects vprint_error' do
      expect_offense(<<~RUBY)
        vprint_error("\#{rhost}:\#{rport} - Failed")
        ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ Lint/RedundantPeerInPrint: Redundant peer/host prefix in print message. The framework auto-prepends host:port via `print_prefix` -- see CONTRIBUTING.md.
      RUBY

      expect_correction(<<~RUBY)
        vprint_error("Failed")
      RUBY
    end
  end

  context 'when message starts with #{ip}:#{rport}' do
    it 'registers an offense and corrects print_status' do
      expect_offense(<<~RUBY)
        print_status("\#{ip}:\#{rport} - Starting FTP login")
        ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ Lint/RedundantPeerInPrint: Redundant peer/host prefix in print message. The framework auto-prepends host:port via `print_prefix` -- see CONTRIBUTING.md.
      RUBY

      expect_correction(<<~RUBY)
        print_status("Starting FTP login")
      RUBY
    end

    it 'registers an offense and corrects print_good' do
      expect_offense(<<~RUBY)
        print_good("\#{ip}:\#{rport} - Login Successful")
        ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ Lint/RedundantPeerInPrint: Redundant peer/host prefix in print message. The framework auto-prepends host:port via `print_prefix` -- see CONTRIBUTING.md.
      RUBY

      expect_correction(<<~RUBY)
        print_good("Login Successful")
      RUBY
    end
  end

  context 'when message starts with #{Rex::Socket.to_authority(rhost, rport)}' do
    it 'registers an offense and corrects print_status' do
      expect_offense(<<~RUBY)
        print_status("\#{Rex::Socket.to_authority(rhost, rport)} - Sending command")
        ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ Lint/RedundantPeerInPrint: Redundant peer/host prefix in print message. The framework auto-prepends host:port via `print_prefix` -- see CONTRIBUTING.md.
      RUBY

      expect_correction(<<~RUBY)
        print_status("Sending command")
      RUBY
    end

    it 'registers an offense and corrects vprint_status' do
      expect_offense(<<~RUBY)
        vprint_status("\#{Rex::Socket.to_authority(rhost, rport)} - Checking")
        ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ Lint/RedundantPeerInPrint: Redundant peer/host prefix in print message. The framework auto-prepends host:port via `print_prefix` -- see CONTRIBUTING.md.
      RUBY

      expect_correction(<<~RUBY)
        vprint_status("Checking")
      RUBY
    end
  end

  context 'when message starts with #{target_host}' do
    it 'registers an offense and corrects print_good' do
      expect_offense(<<~RUBY)
        print_good("\#{target_host} - Detected WordPress")
        ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ Lint/RedundantPeerInPrint: Redundant peer/host prefix in print message. The framework auto-prepends host:port via `print_prefix` -- see CONTRIBUTING.md.
      RUBY

      expect_correction(<<~RUBY)
        print_good("Detected WordPress")
      RUBY
    end

    it 'registers an offense and corrects vprint_status' do
      expect_offense(<<~RUBY)
        vprint_status("\#{target_host} seems to be down")
        ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ Lint/RedundantPeerInPrint: Redundant peer/host prefix in print message. The framework auto-prepends host:port via `print_prefix` -- see CONTRIBUTING.md.
      RUBY

      expect_correction(<<~RUBY)
        vprint_status("seems to be down")
      RUBY
    end
  end

  context 'when message starts with standalone #{rhost}' do
    it 'registers an offense and corrects print_error with separator' do
      expect_offense(<<~RUBY)
        print_error("\#{rhost} - Communication error")
        ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ Lint/RedundantPeerInPrint: Redundant peer/host prefix in print message. The framework auto-prepends host:port via `print_prefix` -- see CONTRIBUTING.md.
      RUBY

      expect_correction(<<~RUBY)
        print_error("Communication error")
      RUBY
    end

    it 'registers an offense and corrects vprint_status with space' do
      expect_offense(<<~RUBY)
        vprint_status("\#{rhost} is not responding")
        ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ Lint/RedundantPeerInPrint: Redundant peer/host prefix in print message. The framework auto-prepends host:port via `print_prefix` -- see CONTRIBUTING.md.
      RUBY

      expect_correction(<<~RUBY)
        vprint_status("is not responding")
      RUBY
    end
  end

  context 'when message starts with standalone #{ip}' do
    it 'registers an offense and corrects vprint_error with separator' do
      expect_offense(<<~RUBY)
        vprint_error("\#{ip} - Connection refused")
        ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ Lint/RedundantPeerInPrint: Redundant peer/host prefix in print message. The framework auto-prepends host:port via `print_prefix` -- see CONTRIBUTING.md.
      RUBY

      expect_correction(<<~RUBY)
        vprint_error("Connection refused")
      RUBY
    end

    it 'registers an offense and corrects print_status with space' do
      expect_offense(<<~RUBY)
        print_status("\#{ip} seems down")
        ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ Lint/RedundantPeerInPrint: Redundant peer/host prefix in print message. The framework auto-prepends host:port via `print_prefix` -- see CONTRIBUTING.md.
      RUBY

      expect_correction(<<~RUBY)
        print_status("seems down")
      RUBY
    end
  end

  context 'when message does not start with a peer prefix' do
    it 'does not flag print_status with no prefix' do
      expect_no_offenses(<<~RUBY)
        print_status("Starting scan")
      RUBY
    end

    it 'does not flag print_status with a plain string' do
      expect_no_offenses(<<~RUBY)
        print_status("Connection to host established")
      RUBY
    end

    it 'does not flag print_status with peer in the middle of the message' do
      expect_no_offenses(<<~RUBY)
        print_status("Connected to \#{peer} successfully")
      RUBY
    end

    it 'does not flag print_status with rhost used non-redundantly' do
      expect_no_offenses(<<~RUBY)
        print_status("Targeting \#{rhost} on port \#{rport}")
      RUBY
    end

    it 'does not flag elog calls (log file output has no print_prefix)' do
      expect_no_offenses(<<~RUBY)
        elog("\#{peer} - Communication error")
      RUBY
    end

    it 'does not flag puts or other non-print methods' do
      expect_no_offenses(<<~RUBY)
        puts "\#{peer} - Debug info"
      RUBY
    end

    it 'does not flag print_status with only a variable' do
      expect_no_offenses(<<~RUBY)
        print_status(msg)
      RUBY
    end

    it 'does not flag print_status with host:port in non-starting position' do
      expect_no_offenses(<<~RUBY)
        print_status("Error on \#{rhost}:\#{rport}")
      RUBY
    end

    it 'does not flag vprint_good with a plain message' do
      expect_no_offenses(<<~RUBY)
        vprint_good("Authentication successful")
      RUBY
    end
  end

  context 'when message contains escape sequences' do
    it 'preserves \\n after peer prefix with no separator' do
      expect_offense(<<~'RUBY')
        print_good("#{peer}\nVersion: #{banner}")
        ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ Lint/RedundantPeerInPrint: Redundant peer/host prefix in print message. The framework auto-prepends host:port via `print_prefix` -- see CONTRIBUTING.md.
      RUBY

      expect_correction(<<~'RUBY')
        print_good("\nVersion: #{banner}")
      RUBY
    end

    it 'preserves \\n after peer prefix with space separator' do
      expect_offense(<<~'RUBY')
        vprint_good("#{peer} \n#{response.body}")
        ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ Lint/RedundantPeerInPrint: Redundant peer/host prefix in print message. The framework auto-prepends host:port via `print_prefix` -- see CONTRIBUTING.md.
      RUBY

      expect_correction(<<~'RUBY')
        vprint_good("\n#{response.body}")
      RUBY
    end

    it 'preserves \\n in middle of remaining text after separator' do
      expect_offense(<<~'RUBY')
        print_good("#{peer} - Databases:\n\n#{results}\n")
        ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ Lint/RedundantPeerInPrint: Redundant peer/host prefix in print message. The framework auto-prepends host:port via `print_prefix` -- see CONTRIBUTING.md.
      RUBY

      expect_correction(<<~'RUBY')
        print_good("Databases:\n\n#{results}\n")
      RUBY
    end

    it 'preserves trailing \\n after Rex::Socket prefix' do
      expect_offense(<<~'RUBY')
        print_good("#{Rex::Socket.to_authority(rhost, rport)} - Exploited successfully\n")
        ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ Lint/RedundantPeerInPrint: Redundant peer/host prefix in print message. The framework auto-prepends host:port via `print_prefix` -- see CONTRIBUTING.md.
      RUBY

      expect_correction(<<~'RUBY')
        print_good("Exploited successfully\n")
      RUBY
    end

    it 'preserves \\t escape sequences' do
      expect_offense(<<~'RUBY')
        print_status("#{peer} - Results:\t#{data}")
        ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ Lint/RedundantPeerInPrint: Redundant peer/host prefix in print message. The framework auto-prepends host:port via `print_prefix` -- see CONTRIBUTING.md.
      RUBY

      expect_correction(<<~'RUBY')
        print_status("Results:\t#{data}")
      RUBY
    end
  end
end
