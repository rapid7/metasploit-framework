import java.awt.color.ColorSpace;

class MyColorSpace extends ColorSpace
{
    private static final long serialVersionUID = 1L;

    public MyColorSpace(int type, int numcomponents)
    {
        super(type,numcomponents);
    }
    public float[] fromCIEXYZ(float[] value) { return null; }
    public float[] toCIEXYZ(float[] value) { return null; }
    public float[] fromRGB(float[] value) { return null; }
    public float[] toRGB(float[] value) { return null;    }
}
