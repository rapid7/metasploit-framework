# frozen_string_literal: true
require 'benchmark'
require 'dbm'

MARSHAL_FILE = "marshal_test.db"
DBM_FILE = "dbm_test"
WRITE_TIMES = 1
READ_TIMES = 100
NUM_INDICES = 10_000
INDICES = ['33', '857', '5022', '8555']

def generate_index
  '0' * (rand * 4096).floor
end

def write_dbm
  File.unlink(DBM_FILE + ".db") if File.exist?(DBM_FILE + ".db")
  handle = DBM.new(DBM_FILE)
  NUM_INDICES.times {|t| handle[t.to_s] = Marshal.dump(generate_index) }
  handle.close
end

def read_dbm
  db = DBM.open(DBM_FILE)
  INDICES.each {|index| Marshal.load(db[index]) }
  db.close
end

def write_marshal
  File.unlink(MARSHAL_FILE) if File.exist?(MARSHAL_FILE)
  handle = {}
  NUM_INDICES.times {|t| handle[t.to_s] = generate_index }
  File.open(MARSHAL_FILE, "wb") {|f| f.write(Marshal.dump(handle)) }
end

def read_marshal
  db = Marshal.load(File.read(MARSHAL_FILE))
  INDICES.each {|index| db[index] }
end

Benchmark.bmbm do |x|
  x.report("marshal-write") { WRITE_TIMES.times { write_marshal } }
  x.report("dbm-write") { WRITE_TIMES.times { write_dbm } }
  x.report("marshal-read ") { READ_TIMES.times { read_marshal } }
  x.report("dbm-read ") { READ_TIMES.times { read_dbm } }
end

File.unlink(MARSHAL_FILE)
File.unlink(DBM_FILE + ".db")

__END__

Rehearsal -------------------------------------------------
marshal-write   0.090000   0.070000   0.160000 (  0.465820)
dbm-write       0.560000   0.570000   1.130000 (  3.045556)
marshal-read    4.640000   3.180000   7.820000 (  7.821978)
dbm-read        0.020000   0.020000   0.040000 (  0.070920)
---------------------------------------- total: 9.150000sec

                    user     system      total        real
marshal-write   0.080000   0.050000   0.130000 (  0.436561)
dbm-write       0.560000   0.550000   1.110000 (  2.030530)
marshal-read    4.670000   3.180000   7.850000 (  7.842232)
dbm-read        0.010000   0.020000   0.030000 (  0.053928)
