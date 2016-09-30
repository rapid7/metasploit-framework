# -*- coding:binary -*-
require 'spec_helper'

RSpec.describe ActiveRecord::ConnectionAdapters::ConnectionPool do
  self.use_transactional_fixtures = false

  def database_configurations
    YAML.load_file(database_configurations_pathname)
  end

  def database_configurations_pathname
    # paths are always Array<String>, but there should only be on 'config/database' entry
    Rails.application.config.paths['config/database'].first
  end

  subject(:connection_pool) do
    ActiveRecord::Base.connection_pool
  end

  # Not all specs require a database connection, and railties aren't being
  # used, so have to manually establish connection.
  before(:example) do
    ActiveRecord::Base.configurations = database_configurations
    spec = ActiveRecord::Base.configurations[Rails.env]
    ActiveRecord::Base.establish_connection(spec)
  end

  after(:example) do
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

    before(:example) do
      ActiveRecord::Base.connection_pool.connection
    end

    context 'in thread with connection' do
      it { is_expected.to be_truthy }
    end

    context 'in thread without connection' do
      it 'should be false' do
        thread = Thread.new do
          expect(Thread.current).not_to eq main_thread
          expect(active_connection?).to be_falsey
        end

        thread.join
      end
    end
  end

  context '#with_connection' do
    def reserved_connection_count
      connection_pool.instance_variable_get(:@reserved_connections).size
    end

    let(:connection_id) do
      main_thread.object_id
    end

    it 'should call #current_connection_id' do
      expect(connection_pool).to receive(
          :current_connection_id
      ).at_least(
          :once
      ).and_call_original

      connection_pool.with_connection { }
    end

    it 'should yield #connection' do
      connection = double('Connection')
      allow(connection_pool).to receive(:connection).and_return(connection)

      expect { |block|
        connection_pool.with_connection(&block)
      }.to yield_with_args(connection)
    end

    context 'with active thread connection' do
      let!(:connection) do
        connection_pool.connection
      end

      after(:example) do
        connection_pool.checkin connection
      end

      it 'should return true from #active_connection?' do
        expect(connection_pool.active_connection?).to be_truthy
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
        expect(connection_pool.active_connection?).to be_falsey
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

            expect(count_change).to eq 1

            connection_pool.with_connection do
              grandchild_count = reserved_connection_count

              expect(grandchild_count).to eq child_count
            end
          end

          after_count = reserved_connection_count

          expect(after_count).to eq before_count
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

            expect(inside).to eq outside
          end
        end
      end
    end
  end
end
