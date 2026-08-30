# frozen_string_literal: true

require 'spec_helper'
require 'rex/post/postgresql'

RSpec.describe Rex::Post::PostgreSQL::Ui::Console::CommandDispatcher::Client do
  let (:client) { described_class.new(nil) }

  before(:each) do
    allow(client).to receive(:process_query).and_call_original
  end

  describe '.process_query' do
    [
      { query: "SELECT \\\nVERSION();", result: 'SELECT VERSION();' },
      { query: "SELECT \VERSION();", result: 'SELECT VERSION();' },
      { query: "SELECT * \\\nFROM dummy_table\\\nWHERE name='example_name'\\\n;", result: "SELECT * FROM dummy_table WHERE name='example_name' ;" },
      { query: "SELECT \\\n* FROM dummy_table\\\n WHERE name='example_name';\n", result: "SELECT * FROM dummy_table WHERE name='example_name';" },
      { query: "INSERT INTO dummy_table VALUES (\\\n'username' \\\n'password_!@£$%^&*()\\'\\\n);", result: "INSERT INTO dummy_table VALUES ( 'username' 'password_!@£$%^&*()\\' );" },
      { query: "DELETE\\\n FROM\\\n dummy_table\\\n WHERE\\\n field='\"\\'\\\n;", result: "DELETE FROM dummy_table WHERE field='\"\\' ;" },
      { query: "SELECT * FROM dummy_table WHERE field='example\\\nfield'", result: "SELECT * FROM dummy_table WHERE field='example field'" },
    ].each do |expected|
      it 'returns the expected value' do
        expect(client.process_query(query: expected[:query])).to eq(expected[:result])
      end
    end
  end
end
