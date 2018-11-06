# -*- coding: binary -*-

module PacketFu
  module PcapNG

    # Hash containing attended structure for each test file.
    # Hash's values are arrays. Each element of these arrays are a section in
    # pcapng file. A section is described as a hash which keys are block types
    # and values number of each type in a section.
    PCAPNG_TEST_FILES = {
      "basic/test001.pcapng"=>[{:idb=>1, :epb=>4, :spb=>0, :unknown=>0}],
      "basic/test002.pcapng"=>[{:idb=>0, :epb=>0, :spb=>0, :unknown=>0}],
      "basic/test003.pcapng"=>[{:idb=>1, :epb=>0, :spb=>0, :unknown=>0}],
      "basic/test004.pcapng"=>[{:idb=>2, :epb=>4, :spb=>0, :unknown=>0}],
      "basic/test005.pcapng"=>[{:idb=>2, :epb=>4, :spb=>0, :unknown=>0}],
      "basic/test006.pcapng"=>[{:idb=>2, :epb=>5, :spb=>0, :unknown=>0}],
      "basic/test007.pcapng"=>[{:idb=>1, :epb=>1, :spb=>0, :unknown=>0}],
      "basic/test008.pcapng"=>[{:idb=>2, :epb=>4, :spb=>0, :unknown=>0}],
      "basic/test009.pcapng"=>[{:idb=>1, :epb=>2, :spb=>0, :unknown=>0}],
      "basic/test010.pcapng"=>[{:idb=>1, :epb=>0, :spb=>4, :unknown=>0}],
      "basic/test011.pcapng"=>[{:idb=>1, :epb=>2, :spb=>2, :unknown=>0}],
      "basic/test012.pcapng"=>[{:idb=>1, :epb=>2, :spb=>2, :unknown=>0}],
      "basic/test013.pcapng"=>[{:idb=>1, :epb=>0, :spb=>0, :unknown=>1}],
      "basic/test014.pcapng"=>[{:idb=>3, :epb=>0, :spb=>0, :unknown=>3}],
      "basic/test015.pcapng"=>[{:idb=>1, :epb=>0, :spb=>0, :unknown=>1}],
      "basic/test016.pcapng"=>[{:idb=>1, :epb=>2, :spb=>2, :unknown=>3}],
      "basic/test017.pcapng"=>[{:idb=>0, :epb=>0, :spb=>0, :unknown=>4}],
      "basic/test018.pcapng"=>[{:idb=>1, :epb=>2, :spb=>2, :unknown=>4}],
      "advanced/test100.pcapng"=>[{:idb=>3, :epb=>3, :spb=>2, :unknown=>5}],
      "advanced/test101.pcapng"=>[{:idb=>3, :epb=>3, :spb=>1, :unknown=>6}],
      "advanced/test102.pcapng"=>[{:idb=>3, :epb=>4, :spb=>1, :unknown=>12}],
      "difficult/test200.pcapng"=>[{:idb=>1, :epb=>0, :spb=>0, :unknown=>0},
                                   {:idb=>1, :epb=>0, :spb=>0, :unknown=>0},
                                   {:idb=>1, :epb=>0, :spb=>0, :unknown=>0}],
      "difficult/test201.pcapng"=>[{:idb=>2, :epb=>1, :spb=>0, :unknown=>1},
                                   {:idb=>1, :epb=>1, :spb=>1, :unknown=>1},
                                   {:idb=>2, :epb=>1, :spb=>0, :unknown=>2}],
      "difficult/test202.pcapng"=>[{:idb=>2, :epb=>3, :spb=>0, :unknown=>4},
                                   {:idb=>1, :epb=>2, :spb=>2, :unknown=>4},
                                   {:idb=>2, :epb=>1, :spb=>0, :unknown=>4}]
    }

  end
end

