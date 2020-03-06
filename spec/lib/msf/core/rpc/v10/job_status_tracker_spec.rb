require 'spec_helper'

require 'msf/core/rpc/v10/rpc_job_status_tracker'

RSpec.describe RpcJobStatusTracker do

  context "With a 1 second ttl " do
    let(:job_status_tracker) { described_class.new(result_ttl=1) }
    let(:job_id) { "super_random_job_id" }


    before(:each) do
      allow(ActiveSupport::Cache::MemoryStore).to receive(:new).and_call_original
    end

    context "A job has completed" do
      before(:each) do
        generic_result = "This is a job that has finished"
        job_status_tracker.completed(job_id, generic_result)
      end

      it 'should show as finished' do
        expect(job_status_tracker).to be_finished(job_id)
      end

      it { expect(ActiveSupport::Cache::MemoryStore).to have_received(:new).with(expires_in: 1) }
    end
  end

  context "With default options" do
    let(:job_status_tracker) { described_class.new }
    let(:job_id) { "super_random_job_id" }
    let(:good_result) { 'yay_success' }
    let(:bad_result) { 'boo_fail' }

    context 'A job is waiting' do
      before(:each) do
        job_status_tracker.waiting(job_id)
      end

      it 'should show as waiting' do
        expect(job_status_tracker).to be_waiting(job_id)
        expect(job_status_tracker.waiting_size).to be(1)
      end

      it 'should not show as running' do
        expect(job_status_tracker).not_to be_running(job_id)
        expect(job_status_tracker.running_size).to be(0)
      end

      it 'should not show as finished' do
        expect(job_status_tracker).not_to be_finished(job_id)
        expect(job_status_tracker.results_size).to be(0)
      end

      context "The job is started" do
        before(:each) do
          job_status_tracker.start(job_id)
        end

        it 'should no longer show as waiting' do
          expect(job_status_tracker).not_to be_waiting(job_id)
          expect(job_status_tracker.waiting_size).to be(0)
        end

        it 'should now show as running' do
          expect(job_status_tracker).to be_running(job_id)
          expect(job_status_tracker.running_size).to be(1)
        end

        it 'should not show as finished' do
          expect(job_status_tracker).not_to be_finished(job_id)
          expect(job_status_tracker.results_size).to be(0)
        end

        context "The job completes successfully" do
          before(:each) do
            job_status_tracker.completed(job_id, good_result)
          end

          it 'should not show as waiting' do
            expect(job_status_tracker).not_to be_waiting(job_id)
            expect(job_status_tracker.waiting_size).to be(0)
          end

          it 'should no longer show as running' do
            expect(job_status_tracker).not_to be_running(job_id)
            expect(job_status_tracker.running_size).to be(0)
          end

          it 'should show as finished' do
            expect(job_status_tracker).to be_finished(job_id)
            expect(job_status_tracker.results_size).to be(1)
          end

          it 'should have a retrievable result' do
            expect(job_status_tracker.result job_id).to eq({result: good_result})
          end

          context "The job is acknowledged" do
            before(:each) do
              job_status_tracker.ack(job_id)
            end

            it 'should not show as waiting' do
              expect(job_status_tracker).not_to be_waiting(job_id)
              expect(job_status_tracker.waiting_size).to be(0)
            end

            it 'should not show as running' do
              expect(job_status_tracker).not_to be_running(job_id)
              expect(job_status_tracker.running_size).to be(0)
            end

            it 'should no longer show as finished' do
              expect(job_status_tracker).not_to be_finished(job_id)
              expect(job_status_tracker.results_size).to be(0)
            end
          end
        end

        context "The job fails" do
          before(:each) do
            job_status_tracker.failed(job_id, bad_result)
          end

          it 'should not show as waiting' do
            expect(job_status_tracker).not_to be_waiting(job_id)
            expect(job_status_tracker.waiting_size).to be(0)
          end

          it 'should no longer show as running' do
            expect(job_status_tracker).not_to be_running(job_id)
            expect(job_status_tracker.running_size).to be(0)
          end

          it 'should show as finished' do
            expect(job_status_tracker).to be_finished(job_id)
            expect(job_status_tracker.results_size).to be(1)
          end

          it 'should have a retrievable result' do
            expect(job_status_tracker.result job_id).to eq({error: bad_result})
          end

          context "The job is acknowledged" do
            before(:each) do
              job_status_tracker.ack(job_id)
            end

            it 'should not show as waiting' do
              expect(job_status_tracker).not_to be_waiting(job_id)
              expect(job_status_tracker.waiting_size).to be(0)
            end

            it 'should not show as running' do
              expect(job_status_tracker).not_to be_running(job_id)
              expect(job_status_tracker.running_size).to be(0)
            end

            it 'should no longer show as finished' do
              expect(job_status_tracker).not_to be_finished(job_id)
              expect(job_status_tracker.results_size).to be(0)
            end
          end
        end

        context 'The job result is not serializable' do
          before(:each) do
            job_status_tracker.completed(job_id, proc {"procs can't be serialized"})
          end

          it 'should show as finished' do
            expect(job_status_tracker).to be_finished(job_id)
            expect(job_status_tracker.results_size).to be(1)
          end

          it 'should have an unexpected_error result' do
            expect(job_status_tracker.result job_id).to have_key(:unexpected_error)
          end
        end
      end
    end
  end
end