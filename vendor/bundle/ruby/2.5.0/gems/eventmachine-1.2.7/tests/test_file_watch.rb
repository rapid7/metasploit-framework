require 'em_test_helper'
require 'tempfile'

class TestFileWatch < Test::Unit::TestCase
  if windows?
    def test_watch_file_raises_unsupported_error
      assert_raises(EM::Unsupported) do
        EM.run do
          file = Tempfile.new("fake_file")
          EM.watch_file(file.path)
        end
      end
    end
  elsif EM.respond_to? :watch_filename
    module FileWatcher
      def file_modified
        $modified = true
      end
      def file_deleted
        $deleted = true
      end
      def unbind
        $unbind = true
        EM.stop
      end
    end

    def setup
      EM.kqueue = true if EM.kqueue?
    end

    def teardown
      EM.kqueue = false if EM.kqueue?
    end

    def test_events
      omit_if(solaris?)
      EM.run{
        file = Tempfile.new('em-watch')
        $tmp_path = file.path

        # watch it
        watch = EM.watch_file(file.path, FileWatcher)
        $path = watch.path

        # modify it
        File.open(file.path, 'w'){ |f| f.puts 'hi' }

        # delete it
        EM.add_timer(0.01){ file.close; file.delete }
      }

      assert_equal($path, $tmp_path)
      assert($modified)
      assert($deleted)
      assert($unbind)
    end

    # Refer: https://github.com/eventmachine/eventmachine/issues/512
    def test_invalid_signature
      # This works fine with kqueue, only fails with linux inotify.
      omit_if(EM.kqueue?)

      EM.run {
        file = Tempfile.new('foo')

        w1 = EventMachine.watch_file(file.path)
        w2 = EventMachine.watch_file(file.path)

        assert_raise EventMachine::InvalidSignature do
          w2.stop_watching
        end

        EM.stop
      }
    end
  else
    warn "EM.watch_file not implemented, skipping tests in #{__FILE__}"

    # Because some rubies will complain if a TestCase class has no tests
    def test_em_watch_file_unsupported
      assert true
    end
  end
end
