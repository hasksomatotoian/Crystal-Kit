CC_64=x86_64-w64-mingw32-gcc

all: bin/dll

bin:
	mkdir bin

bin/dll: bin
	$(CC_64) -shared -o bin/mscorsvc.dll src/DllMain.c

clean:
	rm -f bin/*
