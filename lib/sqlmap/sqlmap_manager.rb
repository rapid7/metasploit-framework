require 'json'

module Sqlmap
  class Manager
    def initialize(session)
      @session = session
    end

    def new_task
      res = @session.get('/task/new')
      if res && res.body 
        parse_response(res.body)
      end
    end

    def delete_task(task_id)
      res = @session.get('/task/' + task_id + '/delete')
      if res && res.body
        parse_response(res.body)
      end

    end

    def set_option(task_id, key, value)
      post = { key => value }
      res = @session.post('/option/' + task_id + '/set', nil, post.to_json, {'ctype' => 'application/json'})
      if res && res.body
        parse_response(res.body)
      end

    end

    def get_options(task_id)
      res = @session.get('/option/' + task_id + '/list')
      if res && res.body
        parse_response(res.body)
      end

    end

    def start_task(task_id, options = {})
      res = @session.post('/scan/' + task_id + '/start' , nil, options.to_json, {'ctype' => 'application/json'})
      if res && res.body
        parse_response(res.body)
      end

    end

    def get_task_status(task_id)
      res = @session.get('/scan/' + task_id + '/status')
      if res && res.body
        parse_response(res.body)
      end

    end

    def get_task_log(task_id)
      res = @session.get('/scan/' + task_id + '/log')
      if res && res.body
        parse_response(res.body)
      end

    end

    def get_task_data(task_id)
      res = @session.get('/scan/' + task_id + '/data')
      if res && res.body
        parse_response(res.body)
      end

    end

    private
    def parse_response(res)
      begin
        res = JSON.parse(res)
      rescue JSON::ParserError
      end

      res
    end
  end
end
