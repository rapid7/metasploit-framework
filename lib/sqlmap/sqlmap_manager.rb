require 'json'

module Sqlmap
  class Manager
    def initialize(session)
      @session = session
    end

    def new_task
      res = @session.get('/task/new')
      parse_response(res)
    end

    def delete_task(task_id)
      res = @session.get('/task/' + task_id + '/delete')
      parse_response(res)
    end

    def set_option(task_id, key, value)
      post = { key => value }
      res = @session.post('/option/' + task_id + '/set', nil, post.to_json, {'ctype' => 'application/json'})
      parse_response(res)
    end

    def get_options(task_id)
      res = @session.get('/option/' + task_id + '/list')
      parse_response(res)
    end

    def start_task(task_id, options = {})
      res = @session.post('/scan/' + task_id + '/start' , nil, options.to_json, {'ctype' => 'application/json'})
      parse_response(res)

    end

    def get_task_status(task_id)
      res = @session.get('/scan/' + task_id + '/status')
      parse_response(res)
    end

    def get_task_log(task_id)
      res = @session.get('/scan/' + task_id + '/log')
      parse_response(res)
    end

    def get_task_data(task_id)
      res = @session.get('/scan/' + task_id + '/data')
      parse_response(res)
    end

    private
    def parse_response(res)
      json = {}
      if res && res.body
        begin
          json = JSON.parse(res.body)
        rescue JSON::ParserError
        end
      end

      json
    end
  end
end
