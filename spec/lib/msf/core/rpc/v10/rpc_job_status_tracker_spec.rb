require 'spec_helper'


RSpec.describe Msf::RPC::RpcJobStatusTracker do
  context 'With default options' do
    let(:job_status_tracker) { described_class.new }
    let(:job_id) { 'super_random_job_id' }
    let(:good_result) { 'yay_success' }
    let(:bad_result) { 'boo_fail' }
    let(:mod) { double('mod') }

    context 'A job is waiting' do
      before(:each) do
        job_status_tracker.waiting(job_id)
      end

      it 'should show as waiting' do
        expect(job_status_tracker).to be_waiting(job_id)
        expect(job_status_tracker.waiting_ids).to eql([job_id])
      end

      it 'should not show as running' do
        expect(job_status_tracker).not_to be_running(job_id)
        expect(job_status_tracker.running_ids).to eql([])
      end

      it 'should not show as finished' do
        expect(job_status_tracker).not_to be_finished(job_id)
        expect(job_status_tracker.result_ids).to eql([])
      end

      context 'The job is started' do
        before(:each) do
          job_status_tracker.start(job_id)
        end

        it 'should no longer show as waiting' do
          expect(job_status_tracker).not_to be_waiting(job_id)
          expect(job_status_tracker.waiting_ids).to eql([])
        end

        it 'should now show as running' do
          expect(job_status_tracker).to be_running(job_id)
          expect(job_status_tracker.running_ids).to eql([job_id])
        end

        it 'should not show as finished' do
          expect(job_status_tracker).not_to be_finished(job_id)
          expect(job_status_tracker.result_ids).to eql([])
        end

        context 'The job completes successfully' do
          before(:each) do
            job_status_tracker.completed(job_id, good_result, mod)
          end

          it 'should not show as waiting' do
            expect(job_status_tracker).not_to be_waiting(job_id)
            expect(job_status_tracker.waiting_ids).to eql([])
          end

          it 'should no longer show as running' do
            expect(job_status_tracker).not_to be_running(job_id)
            expect(job_status_tracker.running_ids).to eql([])
          end

          it 'should show as finished' do
            expect(job_status_tracker).to be_finished(job_id)
            expect(job_status_tracker.result_ids).to eql([job_id])
          end

          it 'should have a retrievable result' do
            expect(job_status_tracker.result(job_id)).to eql({ 'result' => good_result })
          end

          context 'The job is acknowledged' do
            before(:each) do
              job_status_tracker.ack(job_id)
            end

            it 'should not show as waiting' do
              expect(job_status_tracker).not_to be_waiting(job_id)
              expect(job_status_tracker.waiting_ids).to eql([])
            end

            it 'should not show as running' do
              expect(job_status_tracker).not_to be_running(job_id)
              expect(job_status_tracker.running_ids).to eql([])
            end

            it 'should no longer show as finished' do
              expect(job_status_tracker).not_to be_finished(job_id)
              expect(job_status_tracker.result_ids).to eql([])
            end
          end
        end

        context 'The job fails' do
          before(:each) do
            job_status_tracker.failed(job_id, bad_result, mod)
          end

          it 'should not show as waiting' do
            expect(job_status_tracker).not_to be_waiting(job_id)
            expect(job_status_tracker.waiting_ids).to eql([])
          end

          it 'should no longer show as running' do
            expect(job_status_tracker).not_to be_running(job_id)
            expect(job_status_tracker.running_ids).to eql([])
          end

          it 'should show as finished' do
            expect(job_status_tracker).to be_finished(job_id)
            expect(job_status_tracker.result_ids).to eql([job_id])
          end

          it 'should have a retrievable result' do
            expect(job_status_tracker.result(job_id)).to eql({ 'error' => bad_result })
          end

          context 'The job is acknowledged' do
            before(:each) do
              job_status_tracker.ack(job_id)
            end

            it 'should not show as waiting' do
              expect(job_status_tracker).not_to be_waiting(job_id)
              expect(job_status_tracker.waiting_ids).to eql([])
            end

            it 'should not show as running' do
              expect(job_status_tracker).not_to be_running(job_id)
              expect(job_status_tracker.running_ids).to eql([])
            end

            it 'should no longer show as finished' do
              expect(job_status_tracker).not_to be_finished(job_id)
              expect(job_status_tracker.result_ids).to eql([])
            end
          end
        end

        context 'The job result is not serializable' do
          let(:mock_result) { { mock: 'result' } }
          before(:each) do
            allow(mod).to receive(:fullname).and_return('module_name')

            allow(job_status_tracker.instance_variable_get(:@results)).to receive(:write).with(job_id, mock_result.to_json).and_raise Exception, 'Intentional explosion'
            allow(job_status_tracker.instance_variable_get(:@results)).to receive(:write).with(job_id, /error/).and_call_original

            job_status_tracker.completed(job_id, mock_result, mod)
          end

          it 'should show as finished' do
            expect(job_status_tracker).to be_finished(job_id)
            expect(job_status_tracker.result_ids).to eql([job_id])
          end

          it 'should have an error result' do
            expect(job_status_tracker.result(job_id)).to eql(
              {
                'error' => {
                  'message' => 'Job finished but the result could not be stored',
                  'data' => {
                    'mod' => 'module_name'
                  }
                }
              }
            )
          end
        end
      end
    end
  end
end
