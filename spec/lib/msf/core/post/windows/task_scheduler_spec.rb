require 'spec_helper'

RSpec.describe Msf::Post::Windows::TaskScheduler do

  let(:task_name) { Rex::Text.rand_text_alpha(rand(8)) }
  let(:datastore) do
    {
      'ScheduleType' => 'ONSTART',
      'ScheduleModifier' => 1,
      'ScheduleRunAs' => 'SYSTEM',
      'ScheduleObfuscationTechnique' => 'SECURITY_DESC'
    }
  end

  before :example do
    allow(subject).to receive(:datastore).and_return(datastore)
  end

  def create_exploit(info = {})
    mod = Msf::Exploit.allocate
    mod.extend(Msf::PostMixin)
    mod.extend described_class
    mod.send(:initialize, info)
    mod
  end

  subject { create_exploit }

  describe '#task_create' do
    let(:task_cmd) { 'Task Command' }
    let(:task_type) { datastore['ScheduleType'] }
    let(:run_as) { datastore['ScheduleRunAs'] }

    before :example do
      allow(subject).to receive(:schtasks_exec)
      allow(subject).to receive(:delete_reg_key_value)
    end

    context 'with the default options' do
      it 'executes the expected command to create a task' do
        cmd = "schtasks /create /tn \"#{task_name}\" /tr \"#{task_cmd}\" /sc #{task_type} /ru #{run_as} /f"
        expect(subject).to receive(:schtasks_exec).with(cmd)
        subject.task_create(task_name, task_cmd)
      end
      it 'obfuscates the task' do
        reg_key = "#{described_class::TASK_REG_KEY}\\#{task_name}"
        reg_value = described_class::TASK_SD_REG_VALUE
        expect(subject).to receive(:delete_reg_key_value).with(reg_key, reg_value, {})
        subject.task_create(task_name, task_cmd)
      end
    end

    context 'with specific datastore options' do
      before :example do
        datastore.merge!({
          'ScheduleType' => 'MINUTE',
          'ScheduleModifier' => 5,
          'ScheduleRunAs' => 'Admin'
        })
      end

      it 'executes the expected command to create a task' do
        task_mod = datastore['ScheduleModifier']
        cmd = "schtasks /create /tn \"#{task_name}\" /tr \"#{task_cmd}\" /sc #{task_type} /mo #{task_mod} /st 00:00:00 /ru #{run_as} /f"
        expect(subject).to receive(:schtasks_exec).with(cmd)
        subject.task_create(task_name, task_cmd)
      end
    end

    context 'with explicit options passed as argument' do
      let(:opts) do
        {
          task_type: 'HOURLY',
          modifier: 12,
          runas: 'User1'
        }
      end
      it 'executes the expected command to create a task' do
        cmd = "schtasks /create /tn \"#{task_name}\" /tr \"#{task_cmd}\" /sc #{opts[:task_type]} /mo #{opts[:modifier]} /st 00:00:00 /ru #{opts[:runas]} /f"
        expect(subject).to receive(:schtasks_exec).with(cmd)
        subject.task_create(task_name, task_cmd, opts)
      end
    end

    context 'without obfuscation' do
      context 'with specific datastore option' do
        before :example do
          datastore.merge!({ 'ScheduleObfuscationTechnique' => 'NONE' })
        end

        it 'does not obfuscate the task' do
          expect(subject).to_not receive(:delete_reg_key_value)
          subject.task_create(task_name, task_cmd)
        end
      end
    end
  end

  describe '#task_start' do
    before :example do
      allow(subject).to receive(:schtasks_exec)
    end

    it 'executes the expected command to run a task' do
      cmd = "schtasks /run /tn #{task_name}"
      expect(subject).to receive(:schtasks_exec).with(cmd)
      subject.task_start(task_name)
    end
  end

  describe '#task_delete' do
    before :example do
      allow(subject).to receive(:schtasks_exec)
      allow(subject).to receive(:add_reg_key_value)
    end

    context 'with the default options' do
      it 'executes the expected command to delete a task' do
        cmd = "schtasks /delete /tn #{task_name} /f"
        expect(subject).to receive(:schtasks_exec).with(cmd)
        subject.task_delete(task_name)
      end
      it 'desobfuscates the task' do
        reg_key = "#{described_class::TASK_REG_KEY}\\#{task_name}"
        reg_value = described_class::TASK_SD_REG_VALUE
        expect(subject).to receive(:add_reg_key_value).with(reg_key, reg_value, described_class::DEFAULT_SD, 'REG_BINARY', {})
        subject.task_delete(task_name)
      end
    end
  end

  describe '#task_query' do
    before :example do
      allow(subject).to receive(:schtasks_exec)
    end

    context 'on modern Windows' do
      it 'executes the expected command to query a task' do
        cmd = "schtasks /query /tn #{task_name} /v /fo csv /hresult"
        expect(subject).to receive(:schtasks_exec).with(cmd, with_result: true)
        subject.task_query(task_name)
      end
    end

    context 'on older Windows' do
      it 'executes the expected command to query a task' do
        subject.instance_variable_set(:@old_os, true)
        cmd = "schtasks /query /v /fo csv"
        expect(subject).to receive(:schtasks_exec).with(cmd, with_result: true)
        subject.task_query(task_name)
      end
    end
  end


  #
  # Private methods
  #

  describe '#check_compatibility' do
    context 'with Windows XP SP2' do
      before :example do
        allow(subject).to receive(:sysinfo).and_return( { 'OS' => "Windows XP (5.1 Build 2600, Service Pack 2)." } )
      end
      it 'sets `@old_schtasks` and `@old_os` to true' do
        subject.send(:check_compatibility)
        expect(subject.instance_variable_get(:@old_schtasks)).to be true
        expect(subject.instance_variable_get(:@old_os)).to be true
      end
    end

    context 'with Windows Server 2003 SP2' do
      before :example do
        allow(subject).to receive(:sysinfo).and_return( { 'OS' => "Windows .NET Server (5.2 Build 3790, Service Pack 2)." } )
      end
      it 'sets `@old_schtasks` to false and `@old_os` to true' do
        subject.send(:check_compatibility)
        expect(subject.instance_variable_get(:@old_schtasks)).to be false
        expect(subject.instance_variable_get(:@old_os)).to be true
      end
    end

    context 'with Windows Server 2016' do
      before :example do
        allow(subject).to receive(:sysinfo).and_return( { 'OS' => "Windows 2016+ (10.0 Build 14393)." } )
      end
      it 'sets `@old_schtasks` and `@old_os` to false' do
        subject.send(:check_compatibility)
        expect(subject.instance_variable_get(:@old_schtasks)).to be false
        expect(subject.instance_variable_get(:@old_os)).to be false
      end
    end
  end

  describe '#log_and_print' do
    let(:msg) { double('log message') }
    before :example do
      mock_methods = [ :vprint_status, :vprint_good, :vprint_error, :dlog, :ilog, :wlog, :elog ]
      mock_methods.each { |meth| allow(subject).to receive(meth) }
    end

    context 'with the default level (:debug)' do
      it 'prints a status message' do
        expect(subject).to receive(:vprint_status).with(msg)
        subject.send(:log_and_print, msg)
      end
      it 'logs a debug entry' do
        expect(subject).to receive(:dlog).with(msg)
        subject.send(:log_and_print, msg)
      end
    end

    context 'with the :status level' do
      it 'prints a status message' do
        expect(subject).to receive(:vprint_status).with(msg)
        subject.send(:log_and_print, msg, level: :status)
      end
      it 'logs a info entry' do
        expect(subject).to receive(:ilog).with(msg)
        subject.send(:log_and_print, msg, level: :status)
      end
    end

    context 'with the :warning level' do
      it 'prints a warning message' do
        expect(subject).to receive(:vprint_warning).with(msg)
        subject.send(:log_and_print, msg, level: :warning)
      end
      it 'logs a warning entry' do
        expect(subject).to receive(:wlog).with(msg)
        subject.send(:log_and_print, msg, level: :warning)
      end
    end

    context 'with the :error level' do
      it 'prints a error message' do
        expect(subject).to receive(:vprint_error).with(msg)
        subject.send(:log_and_print, msg, level: :error)
      end
      it 'logs a error entry' do
        expect(subject).to receive(:elog).with(msg)
        subject.send(:log_and_print, msg, level: :error)
      end
    end
  end

  describe '#get_schtasks_cmd_string' do
    context 'with the default options' do
      it 'returns the expected command string' do
        cmd_in = %w[/test /flag1 value1]
        cmd_out = "schtasks #{cmd_in.join(' ')}"
        expect(subject.send(:get_schtasks_cmd_string, cmd_in)). to eq(cmd_out)
      end
    end

    context 'with specific datastore options' do
      before :example do
        datastore.merge!({
          'ScheduleRemoteSystem' => '1.2.3.4',
          'ScheduleUsername' => 'msfuser',
          'SchedulePassword' => 'msfpasswd'
        })
      end
      it 'returns the expected command string' do
        cmd_in = %w[/test /flag1 value1]
        cmd_out = "schtasks #{cmd_in.join(' ')} /s 1.2.3.4 /u msfuser /p msfpasswd"
        expect(subject.send(:get_schtasks_cmd_string, cmd_in)). to eq(cmd_out)
      end
    end

    context 'with explicit options passed as argument' do
      let(:opts) do
        {
          remote_system: '1.2.3.4',
          username: 'msfuser',
          password: 'msfpasswd'
        }
      end
      it 'returns the expected command string' do
        cmd_in = %w[/test /flag1 value1]
        cmd_out = "schtasks #{cmd_in.join(' ')} /s 1.2.3.4 /u msfuser /p msfpasswd"
        expect(subject.send(:get_schtasks_cmd_string, cmd_in, opts)). to eq(cmd_out)
      end
    end
  end


  describe '#schtasks_exec' do
    let(:result) { [ Rex::Text.rand_text_alpha(rand(8)), true ] }
    let(:cmd) { double('Command') }
    before :example do
      allow(subject).to receive(:log_and_print)
      allow(subject).to receive(:cmd_exec_with_result).and_return(result)
    end

    context 'without result' do
      context 'when it succeeds' do
        it 'returns nil' do
          expect(subject.send(:schtasks_exec, cmd)).to be nil
        end
      end
      context 'when it fails' do
        it 'raises an error' do
          result[1] = false
          expect { subject.send(:schtasks_exec, cmd) }.to raise_error(described_class::TaskSchedulerError)
        end
      end
    end

    context 'with result' do
      context 'when it succeeds' do
        it 'returns the result' do
          expect(subject.send(:schtasks_exec, cmd, with_result: true)).to eq(result)
        end
      end
      context 'when it fails' do
        it 'returns the result' do
          result[1] = false
          expect(subject.send(:schtasks_exec, cmd, with_result: true)).to eq(result)
        end
      end
    end
  end

  describe '#get_system_privs' do
    let(:session_type) { 'meterpreter' }
    let(:ext) { double('Meterpreter extension') }
    let(:result) { [true, 'technique'] }
    before :example do
      allow(subject).to receive(:log_and_print)
      allow(subject).to receive(:is_system?).and_return(false)
      allow(subject).to receive_message_chain('session.type').and_return(session_type)
      allow(subject).to receive_message_chain('session.ext.priv').and_return(ext)
      allow(subject).to receive_message_chain('session.priv.getsystem').and_return(result)
    end

    it 'tries to get SYSTEM privileges' do
      expect(subject).to receive(:session)
      subject.send(:get_system_privs)
    end

    context 'when the session is alreay in SYSTEM user context' do
      it 'does not try to get SYSTEM privileges' do
        allow(subject).to receive(:is_system?).and_return(true)
        expect(subject).to_not receive(:session)
        subject.send(:get_system_privs)
      end
    end

    context 'when the session is not a Meterpreter session' do
      it 'raises an error' do
        session_type.replace('shell')
        expect { subject.send(:get_system_privs) }.to raise_error(described_class::TaskSchedulerSystemPrivsError)
      end
    end

    context 'when the Meterpreter session does not support the priv extension' do
      it 'raises an error' do
        allow(subject).to receive_message_chain('session.ext.priv').and_return(nil)
        expect { subject.send(:get_system_privs) }.to raise_error(described_class::TaskSchedulerSystemPrivsError)
      end
    end

    context 'when it fails to get SYSTEM privileges' do
      it 'raises an error' do
        result[0] = false
        expect { subject.send(:get_system_privs) }.to raise_error(described_class::TaskSchedulerSystemPrivsError)
      end
    end
  end

  describe '#task_info_field' do
    let(:task_name) { 'fzuZbSwfXc' }
    let(:task_info) {
      info = '"HostName","TaskName","Next Run Time","Status","Logon Mode","Last Run Time","Last Result","Author",'\
             '"Task To Run","Start In","Comment","Scheduled Task State","Idle Time","Power Management","Run As User",'\
             '"Delete Task If Not Rescheduled","Stop Task If Runs X Hours and X Mins","Schedule","Schedule Type",'\
             '"Start Time","Start Date","End Date","Days","Months","Repeat: Every","Repeat: Until: Time",'\
             '"Repeat: Until: Duration","Repeat: Stop If Still Running"'
      info << "\r\n"
      info << '"WINDESK.local","\fzuZbSwfXc","N/A","Ready","Interactive/Background","11/30/1999 12:00:00 AM","267011",'\
              '"WINDEST\Administrator","reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache'\
              '\Tree\DGvtFiFtnZQVmtY" /v "SD"","N/A","N/A","Enabled","Disabled","Stop On Battery Mode, No Start On '\
              'Batteries","SYSTEM","Disabled","72:00:00","Scheduling data is not available in this format.","One Time '\
              'Only","12:00:00 AM","5/10/2020","N/A","N/A","N/A","Disabled","Disabled","Disabled","Disabled"'
      info
    }
    let(:key) { 'Task To Run' }
    let(:result) { 'reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\DGvtFiFtnZQVmtY" /v "SD"' }

    it 'returns the value corresponding to the given key' do
      expect(subject.send(:task_info_field, task_name, task_info, key)).to eq(result)
    end

    context 'when the task name is not found' do
      it 'returns nil' do
        expect(subject.send(:task_info_field, 'NotExisting', task_info, key)).to eq(nil)
      end
    end

    context 'when the task info is empty' do
      it 'returns nil' do
        expect(subject.send(:task_info_field, task_name, '', key)).to eq(nil)
      end
    end

    context 'when the task info only contains a title line' do
      it 'returns nil' do
        task_info.replace(task_info.lines[0])
        expect(subject.send(:task_info_field, task_name, task_info, key)).to eq(nil)
      end
    end

    context 'when the key is not found' do
      it 'returns nil' do
        expect(subject.send(:task_info_field, task_name, task_info, 'NotExisting')).to eq(nil)
      end
    end
  end

  describe '#task_has_run?' do
    let(:last_run_time) { '10/22/2022 10:01:30 PM' }
    before :example do
      allow(subject).to receive(:task_info_field).and_return(last_run_time)
    end

    context 'when the task has run' do
      it 'return true' do
        expect(subject.send(:task_has_run?, 'taskname', 'task_info')).to be true
      end
    end

    context 'when "Last Run Time" is "11/30/1999 12:00:00 AM"' do
      it 'returns false' do
        last_run_time.replace('11/30/1999 12:00:00 AM')
        expect(subject.send(:task_has_run?, 'taskname', 'task_info')).to be false
      end
    end

    context 'when "Last Run Time" is "N/A"' do
      it 'returns false' do
        last_run_time.replace('N/A')
        expect(subject.send(:task_has_run?, 'taskname', 'task_info')).to be false
      end
    end
  end

  describe '#task_is_still_running?' do
    let(:last_result) { described_class::SCHED_S_TASK_RUNNING.to_s }
    before :example do
      allow(subject).to receive(:task_info_field).and_return(last_result)
    end

    context 'when the task is still running' do
      it 'return true' do
        expect(subject.send(:task_is_still_running?, 'taskname', 'task_info')).to be true
      end
    end

    context 'when the task has returned' do
      it 'returns false' do
        last_result.replace('0')
        expect(subject.send(:task_is_still_running?, 'taskname', 'task_info')).to be false
      end
    end
  end

  describe '#run_one_off_task' do
    let(:task_name) { Rex::Text.rand_text_alpha(rand(8..15)) }
    let(:cmd) { double('Command') }
    let(:opts) { { task_type: 'ONCE', runas: 'SYSTEM', obfuscation: 'NONE' } }
    before :example do
      allow(subject).to receive(:log_and_print)
      allow(Rex::Text).to receive(:rand_text_alpha).and_return(task_name)
      allow(subject).to receive(:task_create)
      allow(subject).to receive(:task_start)
      allow(subject).to receive(:task_delete)
    end

    it 'creates, starts and deletes a scheduled task to execute the given command' do
      expect(subject).to receive(:task_create).with(task_name, cmd, opts)
      expect(subject).to receive(:task_start).with(task_name)
      expect(subject).to receive(:task_delete).with(task_name, opts)
      subject.send(:run_one_off_task, cmd)
    end

    context 'when checking if it succeeded' do
      let(:result) { ['info', true] }
      before :example do
        allow(subject).to receive(:log_and_print)
        allow(subject).to receive(:task_query).and_return(result)
        allow(subject).to receive(:task_has_run?).and_return(true)
        allow(subject).to receive(:task_is_still_running?).and_return(false)
        allow(subject).to receive(:task_info_field).and_return('0')
        allow(subject).to receive(:sleep)
      end

      it 'queries the task' do
        expect(subject).to receive(:task_query).with(task_name)
        subject.send(:run_one_off_task, cmd, check_success: true)
      end

      context 'when the command succeeded' do
        it 'returns true' do
          expect(subject.send(:run_one_off_task, cmd, check_success: true)).to be true
        end
      end

      context 'when the command failed' do
        it 'returns true' do
          allow(subject).to receive(:task_info_field).and_return('1')
          expect(subject.send(:run_one_off_task, cmd, check_success: true)).to be false
        end
      end

      context 'when the task is still running' do
        before :example do
          allow(subject).to receive(:task_is_still_running?).and_return(true)
        end

        it 'retries to query the task 5 times until it gives up and returns false' do
          expect(subject).to receive(:task_query).exactly(5).times
          expect(subject.send(:run_one_off_task, cmd, check_success: true)).to be false
        end

        it 'waits 1 sec. between each try' do
          expect(subject).to receive(:sleep).exactly(5).times.with(1)
          expect(subject.send(:run_one_off_task, cmd, check_success: true)).to be false
        end
      end
    end
  end

  describe '#reg_key_value_exists?' do
    let(:reg_key) { 'Registry key' }
    let(:reg_value) { 'Registry key value' }

    context 'when the task is local' do
      before :example do
        allow(subject).to receive(:cmd_exec_with_result).and_return(['', true])
      end

      it 'executes the expected command' do
        cmd = "reg query \"#{reg_key}\" /v \"#{reg_value}\" /reg:64"
        expect(subject).to receive(:cmd_exec_with_result).with(cmd)
        subject.send(:reg_key_value_exists?, reg_key, reg_value)
      end
      it 'returns the result' do
        expect(subject.send(:reg_key_value_exists?, reg_key, reg_value)).to be true
      end
      context 'with old Windows versions' do
        it 'executes the expected command' do
          subject.instance_variable_set(:@old_os, true)
          cmd = "reg query \"#{reg_key}\" /v \"#{reg_value}\""
          expect(subject).to receive(:cmd_exec_with_result).with(cmd)
          subject.send(:reg_key_value_exists?, reg_key, reg_value)
        end
      end
    end

    context 'when the task is remote' do
      let(:cmd) { "reg query \\\"#{reg_key}\\\" /v \\\"#{reg_value}\\\"" }
      before :example do
        allow(subject).to receive(:run_one_off_task).and_return(true)
      end

      context 'when the `ScheduleRemoteSystem` datastore option is set' do
        before :example do
          datastore.merge!( { 'ScheduleRemoteSystem' => '1.2.3.4' } )
        end

        it 'executes the expected command' do
          expect(subject).to receive(:run_one_off_task).with(cmd, check_success: true)
          subject.send(:reg_key_value_exists?, reg_key, reg_value)
        end
        it 'returns the result' do
          expect(subject.send(:reg_key_value_exists?, reg_key, reg_value)).to be true
        end
      end

      context 'when the `:remote_system` hash option is passed as argument' do
        it 'executes the expected command' do
          expect(subject).to receive(:run_one_off_task).with(cmd, check_success: true)
          subject.send(:reg_key_value_exists?, reg_key, reg_value, {remote_system: '1.2.3.4'})
        end
      end
    end
  end

  describe 'delete_reg_key_value' do
    let(:reg_key) { 'Registry key' }
    let(:reg_value) { 'Registry key value' }
    before :example do
      allow(subject).to receive(:log_and_print)
      allow(subject).to receive(:reg_key_value_exists?).and_return(true)
      allow(subject).to receive(:get_system_privs)
    end

    it 'tries to get SYSTEM privileges' do
      allow(subject).to receive(:cmd_exec_with_result).and_return(['', true])
      expect(subject).to receive(:get_system_privs)
      subject.send(:delete_reg_key_value, reg_key, reg_value)
    end

    context 'when it cannot get SYSTEM privileges' do
      it 'raises an error' do
        allow(subject).to receive(:get_system_privs).and_raise(described_class::TaskSchedulerSystemPrivsError)
        expect { subject.send(:delete_reg_key_value, reg_key, reg_value) }.to raise_error(described_class::TaskSchedulerObfuscationError)
      end
    end

    context 'when the key value does not exist' do
      it 'raises an error' do
        allow(subject).to receive(:reg_key_value_exists?).and_return(false)
        expect { subject.send(:delete_reg_key_value, reg_key, reg_value) }.to raise_error(described_class::TaskSchedulerObfuscationError)
      end
    end

    context 'when the task is local' do
      before :example do
        allow(subject).to receive(:cmd_exec_with_result).and_return(['', true])
      end

      it 'executes the expected command' do
        cmd = "reg delete \"#{reg_key}\" /v \"#{reg_value}\" /f /reg:64"
        expect(subject).to receive(:cmd_exec_with_result).with(cmd, nil, 15, { 'UseThreadToken' => true })
        subject.send(:delete_reg_key_value, reg_key, reg_value)
      end

      context 'with old Windows versions' do
        it 'executes the expected command' do
          subject.instance_variable_set(:@old_os, true)
          cmd = "reg delete \"#{reg_key}\" /v \"#{reg_value}\" /f"
          expect(subject).to receive(:cmd_exec_with_result).with(cmd, nil, 15, { 'UseThreadToken' => true })
          subject.send(:delete_reg_key_value, reg_key, reg_value)
        end
      end
    end

    context 'when the task is remote' do
      let(:cmd) { "reg delete \\\"#{reg_key}\\\" /v \\\"#{reg_value}\\\" /f" }
      before :example do
        allow(subject).to receive(:run_one_off_task)
      end

      context 'when the `ScheduleRemoteSystem` datastore option is set' do
        it 'executes the expected command' do
          datastore.merge!( { 'ScheduleRemoteSystem' => '1.2.3.4' } )
          expect(subject).to receive(:run_one_off_task).with(cmd)
          subject.send(:delete_reg_key_value, reg_key, reg_value)
        end
      end

      context 'when the `:remote_system` hash option is passed as argument' do
        it 'executes the expected command' do
          expect(subject).to receive(:run_one_off_task).with(cmd)
          subject.send(:delete_reg_key_value, reg_key, reg_value, {remote_system: '1.2.3.4'})
        end
      end
    end
  end

  describe 'add_reg_key_ralue' do
    let(:reg_key) { 'Registry key' }
    let(:reg_value) { 'Registry key value' }
    let(:reg_data) { 'Registry key value data' }
    let(:reg_type) { 'Registry key type' }
    before :example do
      allow(subject).to receive(:log_and_print)
      allow(subject).to receive(:reg_key_value_exists?).and_return(false)
      allow(subject).to receive(:get_system_privs)
    end

    it 'tries to get SYSTEM privileges' do
      allow(subject).to receive(:cmd_exec_with_result).and_return(['', true])
      expect(subject).to receive(:get_system_privs)
      subject.send(:add_reg_key_value, reg_key, reg_value, reg_data, reg_type)
    end

    context 'when it cannot get SYSTEM privileges' do
      it 'raises an error' do
        allow(subject).to receive(:get_system_privs).and_raise(described_class::TaskSchedulerSystemPrivsError)
        expect { subject.send(:add_reg_key_value, reg_key, reg_value, reg_data, reg_type) }.to raise_error(described_class::TaskSchedulerObfuscationError)
      end
    end

    context 'when the key value already exists' do
      before :example do
        allow(subject).to receive(:reg_key_value_exists?).and_return(true)
      end

      it 'overrides it' do
        expect(subject).to receive(:cmd_exec_with_result).and_return(['', true])
        subject.send(:add_reg_key_value, reg_key, reg_value, reg_data, reg_type)
      end

      context 'when the :override option is set to false' do
        it 'does not override it' do
          expect(subject).to_not receive(:cmd_exec_with_result)
          subject.send(:add_reg_key_value, reg_key, reg_value, reg_data, reg_type, {override: false})
        end
      end

      context 'when the :override option is set to true' do
        it 'overrides it' do
          expect(subject).to receive(:cmd_exec_with_result).and_return(['', true])
          subject.send(:add_reg_key_value, reg_key, reg_value, reg_data, reg_type, {override: true})
        end
      end
    end

    context 'when the task is local' do
      before :example do
        allow(subject).to receive(:cmd_exec_with_result).and_return(['', true])
      end

      it 'executes the expected command' do
        cmd = "reg add \"#{reg_key}\" /v \"#{reg_value}\" /t #{reg_type} /d \"#{reg_data}\" /f /reg:64"
        expect(subject).to receive(:cmd_exec_with_result).with(cmd, nil, 15, { 'UseThreadToken' => true })
        subject.send(:add_reg_key_value, reg_key, reg_value, reg_data, reg_type)
      end

      context 'with old Windows versions' do
        it 'executes the expected command' do
          subject.instance_variable_set(:@old_os, true)
          cmd = "reg add \"#{reg_key}\" /v \"#{reg_value}\" /t #{reg_type} /d \"#{reg_data}\" /f"
          expect(subject).to receive(:cmd_exec_with_result).with(cmd, nil, 15, { 'UseThreadToken' => true })
          subject.send(:add_reg_key_value, reg_key, reg_value, reg_data, reg_type)
        end
      end
    end

    context 'when the task is remote' do
      let(:cmd) { "reg add \\\"#{reg_key}\\\" /v \\\"#{reg_value}\\\" /t #{reg_type} /d \\\"#{reg_data}\\\" /f" }
      before :example do
        allow(subject).to receive(:run_one_off_task)
      end

      context 'when the `ScheduleRemoteSystem` datastore option is set' do
        it 'executes the expected command' do
          datastore.merge!( { 'ScheduleRemoteSystem' => '1.2.3.4' } )
          expect(subject).to receive(:run_one_off_task).with(cmd)
          subject.send(:add_reg_key_value, reg_key, reg_value, reg_data, reg_type)
        end
      end

      context 'when the `:remote_system` hash option is passed as argument' do
        it 'executes the expected command' do
          expect(subject).to receive(:run_one_off_task).with(cmd)
          subject.send(:add_reg_key_value, reg_key, reg_value, reg_data, reg_type, {remote_system: '1.2.3.4'})
        end
      end
    end
  end
end

