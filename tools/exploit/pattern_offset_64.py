import sys

start = ord("0")

def getSize(address):
    global start
    flag1 = int(address[-6:-4], 16)
    flag2 = int(address[-4:-2], 16)
    flag3 = int(address[-2:], 16)
    result = 0
    if flag1 != 0 and flag2 != 0 and flag3 == 0:
        result = (flag1 - start) * 4 - 1
    elif flag1 != 0 and flag2 == 0 and flag3 == 0:
        result = (flag1 - start) * 4 - 2
    elif flag1 == 0 and flag2 == 0 and flag3 != 0:
        result = (flag3 - start) * 4 + 1
    elif flag1 == 0 and flag2 != 0 and flag3 != 0:
        result = (flag3 - start) * 4
    else:
        print "Illegal Address!"
        exit(2)
    return result

def main():
    if len(sys.argv) != 2:
        print "Usage : "
        print "        python getSize.py [OVERWRITED_RIP]"
        exit(1)
    size = getSize(sys.argv[1])
    print "[Length] : [%d]" % size

if __name__ == "__main__":
    main()
