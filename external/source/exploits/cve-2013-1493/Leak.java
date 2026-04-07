class Leak
{
    public volatile int magic;
    public volatile Object obj;
    public volatile Object obj2;
    public volatile Object obj3;
    public volatile Object obj4;

    public Leak(Object o)
    {
        this.magic = -559035650;
        this.obj = o;
    }
}
