#include <stdio.h>
#include <stdlib.h>
#include <SDL2/SDL.h>
#include <sys/stat.h>
#include <zlib.h>
#include <ctype.h>

uint32_t buffer_to_int(uint8_t *buf, int s) {
	// Turn values (each 1 byte) from an array into a single four byte unsigned number.
	return ((uint32_t)buf[s + 0] << 24 | (uint32_t)buf[s + 1] << 16 \
	| (uint32_t)buf[s + 2] << 8 | (uint32_t)buf[s + 3] << 0);

	/* Process Example:
		buf = {0xAA, 0xBB, 0xCC, 0xDD} 
		0xAA000000 (0xAA left shifted 24 bits (or 6 hex characters)) | 
			0xBB0000 (0xBB left shifted 16 bits) |
				0xCC00 (0xCC left shifted 8 bits) |
					0xDD 
						The OR operator will join A and B together; (0b0101 | 0b1000 = 0b1101)
		0xAA000000 |
		0x00BB0000 |
		0x0000CC00 |
		0x000000DD = 0xAABBCCDD
	*/
}

void validate(int cond, const char* msg, int exit_after) {
	// This functions simply checks whether cond is false and if it is, 
		// it prints out a message in STDERR and if exit_after is NONZERO, it will exit with that code
	if (!cond) {
		fprintf(stderr, "%s\n", msg);
		if (exit_after) 
			exit(exit_after);
	}
}

uint8_t paeth_pred(uint8_t a, uint8_t b, uint8_t c) {
    // a -> byte to the left of current byte
	// b -> byte directly above the current byte (previous row)
	// c -> byte top-left of the current byte (previous row)

	int p  = (int)a + (int)b - (int)c; // initial estimate (p = a + b - c)
    int pa = abs(p - (int)a); // abs distance btwn estimated p and a
    int pb = abs(p - (int)b); // abs distance btwm p and b
    int pc = abs(p - (int)c); // abs distance btwn p and c

	// choose the closest estimate (priority: a > b > c)
    if (pa <= pb && pa <= pc) return a; 
    if (pb <= pc) return b;
    return c;
}


int main(int argc, char** argv) {
	// usage: ./pngViewer "png path" ;; argv[0] argv[1]
	validate(argc >= 2, "Please include the path to the png file in the args.", 1);

	// check if the path specified actually exists
	char* pngPath = argv[1];
	struct stat buffer;
	validate(stat(pngPath, &buffer) == 0, "Couldn't find the PNG file specified in the args.", 1);

	// open the file
	FILE *pfile = fopen(pngPath, "rb");
	validate(pfile != NULL, "fopen ran into an issue while opening the png file.", 1);
	
	// read the first 8 bytes of the file
	uint8_t mb_buff[8];
	size_t ret = fread(mb_buff, 1, 8, pfile);
	validate(ret == 8, "Error reading the PNG file. (MB)", 1);

	// expected magic bytes for a png file
	const uint8_t PNG_MAGIC[8] = {
		0x89, 0x50, 0x4E, 0x47,
		0x0D, 0x0A, 0x1A, 0x0A	
	};

	// check each 8 bytes
	for (size_t i = 0; i < 8; i ++) {
		validate(mb_buff[i] == PNG_MAGIC[i], "The file  given is not a PNG file. Magic bytes do not match.", 1);
	}
	
	// After Magic Byte, expect IHDR chunk
	// Each chunk has: Length (4 byte), Type (IHDR, IDAT, IEND), Data: (Length) Bytes, CRC (Cyclic Redundancy Check, type + data): 4 Bytes

	uint8_t length[4] = {0};
	uint8_t type[5] = {0};
	uint8_t crc[4] = {0};
	uint32_t WIDTH = 0;
	uint32_t HEIGHT = 0;	
	int BIT_DEPTH = -1;
	int COLOR_TYPE = -1;
	int COMPRESSION = -1;
	int FILTER = -1;
	int INTERLACE = -1;
	uint8_t* idat = NULL;
	long idat_len = 0;

	while (1) {
		size_t length_ret = fread(length, 1, 4, pfile);
		validate(length_ret == 4, "fread error (length)", 1);

		size_t type_ret = fread(type, 1, 4, pfile);
		validate(type_ret == 4, "fread error (type)", 1);
		
		uint32_t len = buffer_to_int(length, 0);
		uint8_t* data = malloc(len);
		validate(data != NULL, "malloc error", 1);
		size_t data_ret = fread(data, 1, len, pfile);
		validate(data_ret == len, "fread error (data)", 1);

		size_t crc_ret = fread(crc, 1, 4, pfile);
		validate(crc_ret == 4, "fread error (crc)", 1);

		uint32_t crc_int = buffer_to_int(crc, 0);

		uLong crc_calc = crc32(0L, Z_NULL, 0);
		crc_calc = crc32(crc_calc, type, 4);
		if (len > 0) crc_calc = crc32(crc_calc, data, len);
		validate(crc_calc == crc_int, "CRC mismatch on chunk", 1);
		
	
		if (strcmp((char *)type, "IEND") == 0) {
			printf("REACHED END OF PNG");
			break;
		} else if (strcmp((char *)type, "IHDR") == 0) {
			validate(len == 13, "Invalid header chunk", 1);
			
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
				"Unsupported Png :(", 1);

		} else if (strcmp((char *)type, "IDAT") == 0) {
			// concat all the idat chunk data into one buffer
			idat = realloc(idat, idat_len + len);
			validate(idat != NULL, "realloc error", 1);
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
	uint8_t* inflated = malloc(expected);
	validate(inflated != NULL, "malloc error", 1);

	z_stream zs; 
	memset(&zs, 0, sizeof(zs));
	validate(inflateInit(&zs) == Z_OK, "inflateInit failed", 1);

	zs.next_in = idat;
	zs.avail_in = idat_len;
	zs.next_out = inflated;
	zs.avail_out = expected;

	int r = inflate(&zs, Z_FINISH);
	validate(r == Z_STREAM_END, "inflate failed", r);
	validate(zs.total_out == expected, "unexpected inflate size", 1);

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

	uint8_t* pixels = malloc(WIDTH * HEIGHT * 4);
	unsigned int bpp = 4; // bytes per pixel
	uint8_t* prev = NULL; // stores previous row

	for (unsigned int row = 0; row < HEIGHT; row ++) {
		 uint8_t *row_s = inflated + (size_t)(row) * (1 + row_bytes);
		 uint8_t filter_type = row_s[0];
		 uint8_t *src = row_s + 1;
		 uint8_t *dst = pixels + (size_t)(row) * row_bytes; // since we don't need the filter byte

		 switch ((int)filter_type) {
			case 0:
				memcpy(dst, src, row_bytes);
				break;
			case 1: // Sub
				for (unsigned int i = 0; i < row_bytes; i ++) {
					uint8_t left = (i >= bpp) ? dst[i - bpp] : 0;
					dst[i] = (src[i] + left);
				}
				break;
			case 2: // Up
				for (unsigned int i = 0; i < row_bytes; i ++) {
					uint8_t up = prev ? prev[i] : 0;
					dst[i] = (src[i] + up);
				}
				break;
			case 3: // Average
				for (unsigned int i = 0; i < row_bytes; i ++) {
					uint8_t left = (i >= bpp) ? dst[i - bpp] : 0;
					uint8_t up = prev ? prev[i] : 0;
					dst[i] = (uint8_t)(src[i] + (uint8_t)(((int)left + (int)up) / 2));
				}
				break;
			case 4: // Paeth
				for (unsigned int i = 0; i < row_bytes; i ++) {
					uint8_t left = (i >= bpp) ? dst[i - bpp] : 0;
					uint8_t up = prev ? prev[i] : 0;
					uint8_t up_left = (prev && i >= bpp) ? prev[i - bpp] : 0;
					uint8_t pred = paeth_pred(left, up, up_left);
					dst[i] = (src[i] + pred);
				}
				break;
		 }
		 prev = dst;
	}

	SDL_Window *pwindow = SDL_CreateWindow("pngViewer", SDL_WINDOWPOS_CENTERED, SDL_WINDOWPOS_CENTERED, WIDTH, HEIGHT, 0);
	SDL_Surface *psurface = SDL_GetWindowSurface(pwindow);

	SDL_Surface *img = SDL_CreateRGBSurfaceWithFormatFrom(pixels, WIDTH, HEIGHT, 32, WIDTH * 4, SDL_PIXELFORMAT_RGBA32);

	validate(img != NULL, "SDL error", 1);

	SDL_Surface *img_conv = SDL_ConvertSurface(img, psurface->format, 0);
	validate(img_conv != NULL, "convert surface error", 1);

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
