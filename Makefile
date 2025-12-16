all: pngViewer

pngViewer: pngViewer.c
	gcc -Wall -Wextra -O2 -o pngViewer pngViewer.c `sdl2-config --cflags --libs` -lz

clean:
	rm -f pngViewer

.PHONY: all clean

