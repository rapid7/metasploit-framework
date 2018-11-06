#!/usr/bin/env ruby

require 'pg'

# This is another example of how to use COPY FROM, this time as a
# minimal test case used to try to figure out what was going on in
# an issue submitted from a user:
#
#  https://bitbucket.org/ged/ruby-pg/issue/119
#

conn		   = PG.connect( dbname: 'test' )
table_name	   = 'issue_119'
field_list	   = %w[name body_weight brain_weight]
method		   = 0
options		   = { truncate: true }
sql_parameters = ''

conn.set_error_verbosity( PG::PQERRORS_VERBOSE )
conn.exec( "DROP TABLE IF EXISTS #{table_name}" )
conn.exec( "CREATE TABLE #{table_name} ( id SERIAL, name TEXT, body_weight REAL, brain_weight REAL )" )

text = <<-END_DATA
Mountain beaver	1.35	465
Cow	465	423
Grey wolf	36.33	119.5
Goat	27.66	115
Guinea pig	1.04	5.5
Dipliodocus	11700	50
Asian elephant	2547	4603
Donkey	187.1	419
Horse	521	655
Potar monkey	10	115
Cat	3.3	25.6
Giraffe	529	680
Gorilla	207	406
Human	62	1320
African elephant	6654	5712
Triceratops	9400	70
Rhesus monkey	6.8	179
Kangaroo	35	56
Golden hamster	0.12	1
Mouse	0.023	0.4
Rabbit	2.5	12.1
Sheep	55.5	175
Jaguar	100	157
Chimpanzee	52.16	440
Brachiosaurus	87000	154.5
Mole	0.122	3
Pig	192	18
END_DATA

#ActiveRecord::Base.connection_pool.with_connection do |conn|
	conn.transaction do
		rc = conn #.raw_connection
		rc.exec "TRUNCATE TABLE #{table_name};" if options[:truncate]
		sql = "COPY #{table_name} (#{field_list.join(',')}) FROM STDIN #{sql_parameters} "
		p sql
		rc.exec(sql)
		errmsg = nil # scope this outside of the rescue below so it's visible later
		begin
			if method == 1
				rc.put_copy_data text + "\\.\n"
			else
				text.each_line { |line| rc.put_copy_data(line) }
			end
		rescue Errno => err
			errmsg = "%s while reading copy data: %s" % [err.class.name, err.message]
			puts "an error occured"
		end

		if errmsg
			rc.put_copy_end(errmsg)
			puts "ERROR #{errmsg}"
		else
			rc.put_copy_end
		end

		while res = rc.get_result
			st = res.res_status( res.result_status )
			puts "Result of COPY is: %s" % [ st ]
			if res.result_status != PG::PGRES_COPY_IN
				puts res.error_message
			end
		end
		puts "end"
	end #transaction
#end #connection

conn.exec( "SELECT name, brain_weight FROM #{table_name}" ) do |res|
	p res.values
end


