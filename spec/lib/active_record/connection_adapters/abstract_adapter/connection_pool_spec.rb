# -*- coding:binary -*-
require 'spec_helper'

# helps with environment configuration to use for connection to database
require 'metasploit/framework'

# load Mdm::Host for testing
MetasploitDataModels.require_models

describe ActiveRecord::ConnectionAdapters::ConnectionPool do
  def database_configurations
    YAML.load_file(database_configurations_pathname)
  end

  def database_configurations_pathname
    Metasploit::Framework.root.join('config', 'database.yml')
  end

  subject(:connection_pool) do
    ActiveRecord::Base.connection_pool
  end

  # Not all specs require a database connection, and railties aren't being
  # used, so have to manually establish connection.
  before(:each) do
    ActiveRecord::Base.configurations = database_configurations
    spec = ActiveRecord::Base.configurations[Metasploit::Framework.env]
    ActiveRecord::Base.establish_connection(spec)
  end

  after(:each) do
    ActiveRecord::Base.clear_all_connections!
  end

  context '#active_connection?' do
    subject(:active_connection?) do
      connection_pool.active_connection?
    end

    # Let! so that Thread is captured before creating and entering new Threads
    let!(:main_thread) do
      Thread.current
    end

    before(:each) do
      ActiveRecord::Base.connection_pool.connection
    end

    context 'in thread with connection' do
      it { should be_true }
    end

    context 'in thread without connection' do
      it 'should be false' do
        thread = Thread.new do
          Thread.current.should_not == main_thread
          expect(active_connection?).to be_false
        end

        thread.join
      end
    end
  end

  context '#with_connection' do
    def reserved_connection_count
      connection_pool.instance_variable_get(:@reserved_connections).length
    end

    let(:connection_id) do
      main_thread.object_id
    end

    it 'should call #current_connection_id' do
      connection_pool.should_receive(
          :current_connection_id
      ).at_least(
          :once
      ).and_call_original

      connection_pool.with_connection { }
    end

    it 'should yield #connection' do
      connection = double('Connection')
      connection_pool.stub(:connection => connection)

      expect { |block|
        connection_pool.with_connection(&block)
      }.to yield_with_args(connection)
    end

    context 'with active thread connection' do
      let!(:connection) do
        connection_pool.connection
      end

      after(:each) do
        connection_pool.checkin connection
      end

      it 'should return true from #active_connection?' do
        expect(connection_pool.active_connection?).to be_true
      end

      context 'with error' do
        it 'should not release connection' do
          expect {
            # capture error so it doesn't stop example
            expect {
              connection_pool.with_connection do
                # raise error to trigger with_connection's ensure
                raise ArgumentError, 'bad arguments'
              end
            }.to raise_error(ArgumentError)
          }.to change {
            reserved_connection_count
          }.by(0)
        end
      end

      context 'without error' do
        it 'should not release connection' do
          expect {
            connection_pool.with_connection { }
          }.to change{
            reserved_connection_count
          }.by(0)
        end
      end
    end

    context 'without active thread connection' do
      it 'should return false from #active_connection?' do
        expect(connection_pool.active_connection?).to be_false
      end

      context 'with error' do
        it 'should not leave connection created for block' do
          expect {
            # capture error so it doesn't stop example
            expect {
              connection_pool.with_connection do
                # raise error to trigger with_connection's ensure
                raise ArgumentError, 'bad arguments'
              end
            }.to raise_error(ArgumentError)
          }.to change {
            reserved_connection_count
          }.by(0)
        end
      end

      context 'without error' do
        it 'should not leave connection created for block' do
          expect {
            connection_pool.with_connection { }
          }.to change{
            reserved_connection_count
          }.by(0)
        end
      end

      context 'with nested' do
        it 'should not reserve another connection in the nested block' do
          before_count = reserved_connection_count

          connection_pool.with_connection do
            child_count = reserved_connection_count
            count_change = child_count - before_count

            count_change.should == 1

            connection_pool.with_connection do
              grandchild_count = reserved_connection_count

              grandchild_count.should == child_count
            end
          end

          after_count = reserved_connection_count

          after_count.should == before_count
        end
      end

      context 'without with_connection first' do
        it 'should use connection reserved outside with_connection' do
          # Using query methods without a block is expected to retain the
          # reserved connection
          expect {
            # access database outside with_connection block
            Mdm::Host.count
          }.to change {
            reserved_connection_count
          }.by(1)

          outside = reserved_connection_count

          connection_pool.with_connection do
            inside = reserved_connection_count

            inside.should == outside
          end
        end
      end
    end
  end
end
