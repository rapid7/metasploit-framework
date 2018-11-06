module Nexpose

  class Wait
    attr_reader :error_message, :ready, :retry_count, :timeout, :polling_interval

    def initialize(retry_count: nil, timeout: nil, polling_interval: nil)
      @error_message    = 'Default General Failure in Nexpose::Wait'
      @ready            = false
      @retry_count      = retry_count.to_i
      @timeout          = timeout
      @polling_interval = polling_interval
    end

    def ready?
      @ready
    end

    def for_report(nexpose_connection:, report_id:)
      poller = Nexpose::Poller.new(timeout: @timeout, polling_interval: @polling_interval)
      poller.wait(report_status_proc(nexpose_connection: nexpose_connection, report_id: report_id))
      @ready = true
    rescue Timeout::Error
      @ready = false
      retry if timeout_retry?
      @error_message = "Timeout Waiting for Report to Generate - Report Config ID: #{report_id}"
    rescue NoMethodError => error
      @ready = false
      @error_message = "Error Report Config ID: #{report_id} :: Report Probably Does Not Exist :: #{error}"
    rescue => error
      @ready = false
      @error_message = "Error Report Config ID: #{report_id} :: #{error}"
    end

    def for_integration(nexpose_connection:, scan_id:, status: 'finished')
      poller = Nexpose::Poller.new(timeout: @timeout, polling_interval: @polling_interval)
      poller.wait(integration_status_proc(nexpose_connection: nexpose_connection, scan_id: scan_id, status: status))
      @ready = true
    rescue Timeout::Error
      @ready = false
      retry if timeout_retry?
      @error_message = "Timeout Waiting for Integration Status of '#{status}' - Scan ID: #{scan_id}"
    rescue Nexpose::APIError => error
      @ready = false
      @error_message = "API Error Waiting for Integration Scan ID: #{scan_id} :: #{error.req.error}"
    end

    def for_judgment(proc:, desc:)
      poller = Nexpose::Poller.new(timeout: @timeout, polling_interval: @polling_interval)
      poller.wait(proc)
      @ready = true
    rescue Timeout::Error
      @ready = false
      retry if timeout_retry?
      @error_message = "Timeout Waiting for Judgment to Judge. #{desc}"
    end

    private

    def report_status_proc(nexpose_connection:, report_id:)
      proc { nexpose_connection.last_report(report_id).status == 'Generated' }
    end

    def integration_status_proc(nexpose_connection:, scan_id:, status:)
      proc { nexpose_connection.scan_status(scan_id).downcase == status.downcase }
    end

    def timeout_retry?
      if @retry_count > 0
        @retry_count -= 1
        true
      else
        false
      end
    end

  end

  class Poller
    ## Stand alone object to handle waiting logic.
    attr_reader :timeout, :polling_interval, :poll_begin

    def initialize(timeout: nil, polling_interval: nil)
      global_timeout = set_global_timeout
      @timeout = timeout.nil? ? global_timeout : timeout

      global_polling = set_polling_interval
      @polling_interval = polling_interval.nil? ? global_polling : polling_interval
    end

    def wait(condition)
      @poll_begin = Time.now
      loop do
        break if condition.call
        raise Timeout::Error if @poll_begin + @timeout < Time.now
        sleep @polling_interval
      end
    end

    private

    def set_global_timeout
      default_timeout = 120
      ENV['GLOBAL_TIMEOUT'].nil? ? default_timeout : ENV['GLOBAL_TIMEOUT']
    end

    def set_polling_interval
      default_polling = 1
      ENV['GLOBAL_POLLING_INTERVAL'].nil? ? default_polling : ENV['GLOBAL_POLLING_INTERVAL']
    end

  end

end
