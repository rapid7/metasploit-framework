import java.awt.image.BufferedImage;
import java.awt.image.ColorModel;
import java.awt.image.SampleModel;

class MyBufferedImage extends BufferedImage
{
    int _fakeType;
    ColorModel _fakeColorModel;
    SampleModel _fakeSampleModel;

    public MyBufferedImage(int width, int height, int imageType, int fakeType, ColorModel fakeColorModel, SampleModel fakeSampleModel)
    {
        super(width,height, imageType);

        this._fakeType = fakeType;
        this._fakeColorModel = fakeColorModel;
        this._fakeSampleModel = fakeSampleModel;
    }

    public int getType()
    {
        String caller = java.lang.Thread.currentThread().getStackTrace()[2].toString();
        if (caller.contains("ICC_Transform.getImageLayout(")) {
            return this._fakeType;
        }

        return super.getType();
    }

    public ColorModel getColorModel()
    {
        String caller = java.lang.Thread.currentThread().getStackTrace()[2].toString();
        if ((caller.contains("ICC_Transform.getImageLayout(")) || (caller.contains("CMMImageLayout.<init>("))) {
            return this._fakeColorModel;
        }

        return super.getColorModel();
    }

    public SampleModel getSampleModel()
    {
        String caller = java.lang.Thread.currentThread().getStackTrace()[2].toString();
        if (caller.contains("ICC_Transform.getImageLayout(")) {
            return this._fakeSampleModel;
        }

        return super.getSampleModel();
    }
}
