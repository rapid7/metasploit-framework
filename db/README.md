This directory contains the following files:

- `modules_metadata_base.json`, which contains information about all modules within Metasploit.
- `schema.rb`, which is auto-generated from the current state of the database schema maintained by Rails ActiveRecord.
  This file is auto-generated from the current state of the database.

`schema.rb` is the source Rails uses to define your schema when running `bin/rails db:schema:load`. When creating a new 
database, `bin/rails db:schema:load` tends to be faster and is potentially less error-prone than running all of your 
migrations from scratch. Old migrations may fail to apply correctly if those migrations use external dependencies or 
application code. We _strongly_ recommend that you check this file into your version control system.
