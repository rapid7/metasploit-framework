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

        context 'The job result contains framework objects that cannot be JSON-serialized' do
          let(:framework_object) do
            klass = Class.new do
              def initialize
                @self_ref = self
              end

              def to_s
                'framework-object-summary'
              end
            end
            klass.new
          end
          let(:host_result) do
            {
              '192.0.2.10' => {
                successful_logins: [framework_object],
                successful_sessions: [framework_object],
                banner: 'SMB 3.0'
              }
            }
          end

          before(:each) do
            job_status_tracker.completed(job_id, host_result, mod)
          end

          it 'preserves the outer hash structure' do
            stored = job_status_tracker.result(job_id)
            expect(stored['result']['192.0.2.10']).to be_a(Hash)
            expect(stored['result']['192.0.2.10'].keys)
              .to include('successful_logins', 'successful_sessions', 'banner')
          end

          it 'stringifies non-primitive leaves via to_s' do
            stored = job_status_tracker.result(job_id)
            expect(stored['result']['192.0.2.10']['successful_logins'])
              .to eq(['framework-object-summary'])
            expect(stored['result']['192.0.2.10']['successful_sessions'])
              .to eq(['framework-object-summary'])
          end

          it 'preserves JSON-primitive leaves as-is' do
            stored = job_status_tracker.result(job_id)
            expect(stored['result']['192.0.2.10']['banner']).to eq('SMB 3.0')
          end

          it 'does not fall through to the "could not be stored" fallback' do
            expect(job_status_tracker.result(job_id)).not_to have_key('error')
          end
        end

        context 'The job result contains a Msf::Exploit::CheckCode' do
          let(:check_result) { Msf::Exploit::CheckCode::Vulnerable }
          let(:mock_result) { { host: '192.0.2.10', check: check_result } }

          before(:each) do
            job_status_tracker.completed(job_id, mock_result, mod)
          end

          it 'preserves the CheckCode round-trip through JSON' do
            stored = job_status_tracker.result(job_id)
            expect(stored['result']['check']).to eq(check_result.to_json.then { |s| ::JSON.parse(s) })
          end
        end

        context 'The job result preserves JSON primitive types' do
          let(:mock_result) do
            {
              count: 3,
              rate: 1.5,
              found: true,
              missing: nil,
              tag: :scanner
            }
          end

          before(:each) do
            job_status_tracker.completed(job_id, mock_result, mod)
          end

          it 'preserves numbers, booleans, nil, and stringifies symbols per JSON conventions' do
            stored = job_status_tracker.result(job_id)['result']
            expect(stored['count']).to eq(3)
            expect(stored['rate']).to eq(1.5)
            expect(stored['found']).to be true
            expect(stored['missing']).to be_nil
            expect(stored['tag']).to eq('scanner')
          end
        end
      end
    end
  end
end
