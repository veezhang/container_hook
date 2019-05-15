container_hook_so = container_hook.so

$(container_hook_so): container_hook.c
	gcc -std=c99 -Wall -shared -g -fPIC -Wl,--no-as-needed -ldl container_hook.c -o $(container_hook_so)
	gcc container_hook_test.c -o container_hook_test

clean:
	rm -f *.o *.so detection.so.* container_hook_test

.PHONY: clean
