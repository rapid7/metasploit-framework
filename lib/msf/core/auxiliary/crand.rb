module Msf

###
#
# This module provides a complete port of the libc rand() and srand() functions.
# It is used by the NETGEAR WNR2000v5 auxiliary and exploit modules, but might
# be useful for any other module that needs to emulate C's random number generator.
#
# Author: Pedro Ribeiro (pedrib@gmail.com) / Agile Information Security
#
###
module Auxiliary::CRand

  attr_accessor :randtbl
  attr_accessor :unsafe_state

####################
# ported from https://git.uclibc.org/uClibc/tree/libc/stdlib/random.c
# and https://git.uclibc.org/uClibc/tree/libc/stdlib/random_r.c

  TYPE_3 = 3
  BREAK_3 = 128
  DEG_3 = 31
  SEP_3 = 3

  def initialize(info = {})
    super
    
    @randtbl =
    [
      # we omit TYPE_3 from here, not needed
      -1726662223, 379960547, 1735697613, 1040273694, 1313901226,
      1627687941, -179304937, -2073333483, 1780058412, -1989503057,
      -615974602, 344556628, 939512070, -1249116260, 1507946756,
      -812545463, 154635395, 1388815473, -1926676823, 525320961,
      -1009028674, 968117788, -123449607, 1284210865, 435012392,
      -2017506339, -911064859, -370259173, 1132637927, 1398500161,
      -205601318,
    ]

    @unsafe_state = { 
      "fptr" => SEP_3,
      "rptr" => 0,
      "state" => 0,
      "rand_type" => TYPE_3,
      "rand_deg" => DEG_3,
      "rand_sep" => SEP_3,
      "end_ptr" => DEG_3
    }
  end

  # Emulate the behaviour of C's srand
  def srandom_r (seed)
    state = @randtbl
    if seed == 0
      seed = 1
    end
    state[0] = seed
    
    dst = 0
    word = seed
    kc = DEG_3
    for i in 1..(kc-1)
      hi = word / 127773
      lo = word % 127773
      word = 16807 * lo - 2836 * hi
      if (word < 0)
        word += 2147483647
      end
      dst += 1
      state[dst] = word
    end
    
    @unsafe_state['fptr'] = @unsafe_state['rand_sep']
    @unsafe_state['rptr'] = 0
    
    kc *= 10
    kc -= 1
    while (kc >= 0)
      random_r
      kc -= 1
    end
  end
    
  # Emulate the behaviour of C's rand  
  def random_r
    buf = @unsafe_state
    state = buf['state']
    
    fptr = buf['fptr']
    rptr = buf['rptr']
    end_ptr = buf['end_ptr']
    val = @randtbl[fptr] += @randtbl[rptr]
    
    result = (val >> 1) & 0x7fffffff
    fptr += 1
    if (fptr >= end_ptr)
      fptr = state
      rptr += 1
    else
      rptr += 1
      if (rptr >= end_ptr)
        rptr = state
      end
    end
    buf['fptr'] = fptr
    buf['rptr'] = rptr
    
    result
  end

end
end
