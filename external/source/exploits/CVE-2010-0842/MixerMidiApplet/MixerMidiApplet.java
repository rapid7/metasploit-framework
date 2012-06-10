import java.applet.Applet;
import java.awt.Graphics;
import java.io.*;

import java.net.*;

import javax.sound.midi.*;
import com.sun.media.sound.*;
import javax.sound.midi.*;   

 
public class MixerMidiApplet extends Applet {

  Sequencer sequencer = null;
  Sequence mySeq = null;    
           
  @Override
  public void start() {
    	
     //What midi file do we need to play.. ?
         	    
    String filename = getParameter("MIDIFILE");
       
    // Main code, its in a try thanks to all the calls that 
    // might theoretically go wrong.
    try {
      // Get a list of midi devices installed. We added our own device 
      // (well actually only a device provider) that returns a 
      // MixerSequencer. Another option would be to use the 
      // default RealtimeSequencer and then use a RMF midifile, 
      // that way the RealtimeSequencer will be using a MixerSequencer.
      // But then we need our own MidiFileReader and return 
      // the correct MidiFile info, this is much easier :)
      MidiDevice.Info[] infos = MidiSystem.getMidiDeviceInfo();
      
      // infos[0] should be our MixerSequencerProvider
      MidiDevice mixer = MidiSystem.getMidiDevice(infos[0]);
      
      // Turn it into a sequencer
      sequencer = (Sequencer)mixer;

      // Open it      
      sequencer.open();
                
      // Get the input stream from the midi file so we 
      // can use that in setSequencer
      InputStream midistream = getClass().getResourceAsStream(filename);

      //We need to convert the InputStream to an byteArrayInputStream 
      // to avoid 'ERROR! java.io.IOException: mark/reset not supported'
      // exceptions
      ByteArrayOutputStream bos = new ByteArrayOutputStream();
      byte[] buf = new byte[1024];
      int c;
      while((c = midistream.read(buf)) != -1) {
      	bos.write(buf, 0, c);
      }
      
      ByteArrayInputStream bamidistream = new ByteArrayInputStream(bos.toByteArray());

      // This will call nOpenRmfSequencer wich will the RMF SONG BlockID
      // as our pSong->userReference
      sequencer.setSequence(bamidistream);

      // We add a controler at the first array field.
      MyController mc = new MyController();
      
      // This will fil the right tables, and add our newly found 
      // SONG id (in the .rmf file) where we want it.
      sequencer.addControllerEventListener(mc, new int[] {0});

      // Start playing the midi file, then find a nice 
      // 00 B0 80 00 secquence and make us happy 
      sequencer.start();
     
    } catch (Exception ex) {
        System.out.println("ERROR! " + ex);
    }

  }
    
    public void run() {
        
    }    

}