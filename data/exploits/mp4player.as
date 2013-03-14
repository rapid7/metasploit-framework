function randText(newLength:Number):String{
  var a:String = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
  var alphabet:Array = a.split("");
  var randomLetter:String = "";
  for (var i:Number = 0; i < newLength; i++){
    randomLetter += alphabet[Math.floor(Math.random() * alphabet.length)];
  }
  return randomLetter;
}

var connect_nc:NetConnection = new NetConnection();
connect_nc.connect(null);

var stream_ns:NetStream = new NetStream(connect_nc);
stream_ns.onStatus = function(p_evt:Object):Void { }


video.attachVideo(stream_ns);

stream_ns.play(randText(Math.floor(Math.random() * 8) + 4) + ".mp4");


