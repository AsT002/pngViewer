#include <stdio.h>
#include <stdlib.h>
#include <SDL2/SDL.h>
#include <sys/stat.h>
#include <zlib.h>
#include <ctype.h>

uint32_t buffer_to_int(unsigned char *buf, int s) {
	return ((int)buf[s+0]<<24)|((int)buf[s+1]<<16)|((int)buf[s+2]<<8)|((int)buf[s+3]<<0);
}

void validate(int cond, const char* msg, int exit_after) {
	if (!cond) {
		printf("%s", msg);
		if (exit_after) 
			exit(exit_after);
	}
}

unsigned char paeth_pred(unsigned char a, unsigned char b, unsigned char c) {
    int p  = (int)a + (int)b - (int)c;
    int pa = abs(p - (int)a);
    int pb = abs(p - (int)b);
    int pc = abs(p - (int)c);

    if (pa <= pb && pa <= pc) return a;
    if (pb <= pc) return b;
    return c;
}


int main(int argc, char** argv) {
	validate(argc >= 2, "Please include the path to the png file in the args.\n", 1);

	char* pngPath = argv[1];
	struct stat buffer;
	validate(stat(pngPath, &buffer) == 0, "Couldn't find the PNG file specified in the args.\n", 1);

	FILE *pfile = fopen(pngPath, "rb");
	validate(pfile != NULL, "fopen ran into an issue while opening the png file.\n", 1);
	
	unsigned char mb_buff[8];
	size_t ret = fread(mb_buff, 1, 8, pfile);
	validate(ret == 8, "Error reading the PNG file. (MB)\n", 1);

	const uint8_t png_magic[8] = {
		0x89, 0x50, 0x4E, 0x47,
		0x0D, 0x0A, 0x1A, 0x0A	
	};

	int is_png = 1;
	for (size_t i = 0; i < 8; i ++) {
		if (mb_buff[i] != png_magic[i]) { 
			is_png = 0; 
			break; 
		}
	}
	validate(is_png, "The file given is not a PNG file. Magic bytes do not match.\n", 1);
	
	// After Magic Byte, expect IHDR chunk
	// Each chunk has: Length (4 byte), Type (IHDR, IDAT, IEND), Data: (Length) Bytes, CRC (Cyclic Redundancy Check, type + data): 4 Bytes

	unsigned char length[4] = {0};
	unsigned char type[5] = {0};
	unsigned char crc[4] = {0};
	uint32_t WIDTH = -1;
	uint32_t HEIGHT = -1;	
	int BIT_DEPTH = -1;
	int COLOR_TYPE = -1;
	int COMPRESSION = -1;
	int FILTER = -1;
	int INTERLACE = -1;
	unsigned char *idat = NULL;
	long idat_len = 0;

	while (1) {
		size_t length_ret = fread(length, 1, 4, pfile);
		validate(length_ret == 4, "fread error (length)\n", 1);

		size_t type_ret = fread(type, 1, 4, pfile);
		validate(type_ret == 4, "fread error (type)\n", 1);
		
		uint32_t len = buffer_to_int(length, 0);
		unsigned char* data = (unsigned char *)malloc(len);
		validate(data != NULL, "malloc error\n", 1);
		size_t data_ret = fread(data, 1, len, pfile);
		validate(data_ret == len, "fread error (data)\n", 1);

		size_t crc_ret = fread(crc, 1, 4, pfile);
		validate(crc_ret == 4, "fread error (crc)\n", 1);

		uint32_t crc_int = buffer_to_int(crc, 0);

		uLong crc_calc = crc32(0L, Z_NULL, 0);
		crc_calc = crc32(crc_calc, type, 4);
		if (len > 0) crc_calc = crc32(crc_calc, data, len);
		validate(crc_calc == crc_int, "CRC mismatch on chunk\n", 1);
		
	
		if (strcmp((char *)type, "IEND") == 0) {
			printf("REACHED END OF PNG\n");
			break;
		} else if (strcmp((char *)type, "IHDR") == 0) {
			validate(len == 13, "Invalid header chunk\n", 1);
			
			WIDTH = buffer_to_int(data, 0);
			HEIGHT = buffer_to_int(data, 4);	
			BIT_DEPTH = (0x0) | data[8];
			COLOR_TYPE = (0x0) | data[9];
			COMPRESSION = (0x0) | data[10];
			FILTER = (0x0) | data[11];
			INTERLACE = (0x0) | data[12];	
			printf("WIDTH: %d;\nHEIGHT: %d;"
				"\nBIT DEPTH: %d;\nCOLOR TYPE: %d;"
				"\nCOMPRESSION: %d;\nFILTER: %d;"
				"\nINTERLACE: %d;\n", WIDTH, \
				HEIGHT, BIT_DEPTH, \
				COLOR_TYPE, COMPRESSION, FILTER, INTERLACE);
		
			validate(COLOR_TYPE == 6 && \
				BIT_DEPTH == 8 && COMPRESSION == 0 && \
				FILTER == 0 && INTERLACE == 0, \
				"Unsupported Png :(\n", 1);

		} else if (strcmp((char *)type, "IDAT") == 0) {
			// concat all the idat chunk data into one buffer
			idat = realloc(idat, idat_len + len);
			validate(idat != NULL, "realloc error\n", 1);
			memcpy(idat + idat_len, data, len);
			idat_len += len;
		} else if (islower((char)type[0]) || strcmp((char *)type, "PLTE") == 0) {
			free(data);
			continue;
		}  
		else {
			printf("Invalid chunk type %s.\n", (char *)type);
			exit(1);
		}
		free(data);
	}

	
	// inflate the concat'd idat with zlib
	uint32_t row_bytes = WIDTH * 4;
	uint32_t expected = HEIGHT * (1 + row_bytes);
	unsigned char *inflated = malloc(expected);
	validate(inflated != NULL, "malloc error\n", 1);

	z_stream zs; 
	memset(&zs, 0, sizeof(zs));
	validate(inflateInit(&zs) == Z_OK, "inflateInit failed\n", 1);

	zs.next_in = idat;
	zs.avail_in = idat_len;
	zs.next_out = inflated;
	zs.avail_out = expected;

	int r = inflate(&zs, Z_FINISH);
	validate(r == Z_STREAM_END, "inflate failed\n", r);
	validate(zs.total_out == expected, "unexpected inflate size\n", 1);

	inflateEnd(&zs);

	// unfilter (each row contains a filter byte at the start)
	/*
	filters: (https://www.libpng.org/pub/png/spec/1.2/PNG-Filters.html)
		0 None,
		1 Sub,
		2 Up,
		3 Avg,
		4 Paeth
	*/

	unsigned char* pixels = malloc(WIDTH * HEIGHT * 4);
	unsigned int bpp = 4; // bytes per pixel
	unsigned char* prev = NULL; // stores previous row

	for (unsigned int row = 0; row < HEIGHT; row ++) {
		 unsigned char *row_s = inflated + (size_t)(row) * (1 + row_bytes); // cast should be safe as row shouldn't be negative
		 unsigned char filter_type = row_s[0];
		 unsigned char *src = row_s + 1;
		 unsigned char *dst = pixels + (size_t)(row) * row_bytes; // since we don't need the filter byte

		 switch ((int)filter_type) {
			case 0:
				memcpy(dst, src, row_bytes);
				break;
			case 1: // Sub
				for (unsigned int i = 0; i < row_bytes; i ++) {
					unsigned char left = (i >= bpp) ? dst[i - bpp] : 0;
					dst[i] = (src[i] + left);
				}
				break;
			case 2: // Up
				for (unsigned int i = 0; i < row_bytes; i ++) {
					unsigned char up = prev ? prev[i] : 0;
					dst[i] = (src[i] + up);
				}
				break;
			case 3: // Average
				for (unsigned int i = 0; i < row_bytes; i ++) {
					unsigned char left = (i >= bpp) ? dst[i - bpp] : 0;
					unsigned char up = prev ? prev[i] : 0;
					dst[i] = (unsigned char)(src[i] + (unsigned char)(((int)left + (int)up) / 2));
				}
				break;
			case 4: // Paeth
				for (unsigned int i = 0; i < row_bytes; i ++) {
					unsigned char left = (i >= bpp) ? dst[i - bpp] : 0;
					unsigned char up = prev ? prev[i] : 0;
					unsigned char up_left = (prev && i >= bpp) ? prev[i - bpp] : 0;
					unsigned char pred = paeth_pred(left, up, up_left);
					dst[i] = (src[i] + pred);
				}
				break;
		 }
		 prev = dst;
	}

	SDL_Window *pwindow = SDL_CreateWindow("pngViewer", SDL_WINDOWPOS_CENTERED, SDL_WINDOWPOS_CENTERED, WIDTH, HEIGHT, 0);
	SDL_Surface *psurface = SDL_GetWindowSurface(pwindow);

	SDL_Surface *img = SDL_CreateRGBSurfaceWithFormatFrom(pixels, WIDTH, HEIGHT, 32, WIDTH * 4, SDL_PIXELFORMAT_RGBA32);

	validate(img != NULL, "SDL error\n", 1);

	SDL_Surface *img_conv = SDL_ConvertSurface(img, psurface->format, 0);
	validate(img_conv != NULL, "convert surface error\n", 1);

	SDL_BlitSurface(img_conv, NULL, psurface, NULL);
	SDL_UpdateWindowSurface(pwindow);

	SDL_Event e;
	int running = 1;

	while (running) {
		while (SDL_PollEvent(&e)) {
			if (e.type == SDL_QUIT) running = 0;
		}
	}

	free(idat);
	SDL_FreeSurface(img_conv);
	SDL_FreeSurface(img);
	SDL_DestroyWindow(pwindow);
	SDL_Quit();
	free(pixels);
	free(inflated);
}
