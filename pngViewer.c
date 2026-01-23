#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/stat.h>
#include <zlib.h>
#include <ctype.h>
#if defined(__APPLE__)
#include <SDL.h>
#elif defined(__linux__)
#include <SDL2/SDL.h>
#endif

uint32_t buffer_to_int(const uint8_t *buf, int s)
{
	// Read 4 bytes big-endian from buf[s].
	return ((uint32_t)buf[s + 0] << 24 | (uint32_t)buf[s + 1] << 16 | (uint32_t)buf[s + 2] << 8 | (uint32_t)buf[s + 3] << 0);
}

uint8_t paeth_pred(uint8_t a, uint8_t b, uint8_t c)
{
	// a -> byte to the left of current byte
	// b -> byte directly above the current byte (previous row)
	// c -> byte top-left of the current byte (previous row)

	int p = (int)a + (int)b - (int)c; // initial estimate (p = a + b - c)
	int pa = abs(p - (int)a);		  // abs distance btwn estimated p and a
	int pb = abs(p - (int)b);		  // abs distance btwm p and b
	int pc = abs(p - (int)c);		  // abs distance btwn p and c

	// choose the closest estimate (priority: a > b > c)
	if (pa <= pb && pa <= pc)
		return a;
	if (pb <= pc)
		return b;
	return c;
}

int main(int argc, char **argv)
{
	// usage: ./pngViewer "<png path>"
	if (argc < 2)
	{
		fprintf(stderr, "Usage error: missing PNG path argument.\n");
		exit(1);
	}

	// check if the path specified actually exists
	const char *pngPath = argv[1];
	struct stat buffer;
	if (stat(pngPath, &buffer) != 0)
	{
		fprintf(stderr, "File error: PNG path not found: %s\n", pngPath);
		exit(1);
	}

	// open the file
	FILE *pfile = fopen(pngPath, "rb");
	if (pfile == NULL)
	{
		fprintf(stderr, "File error: failed to open PNG for reading: %s\n", pngPath);
		exit(1);
	}

	// read the first 8 bytes of the file
	uint8_t mb_buff[8];
	size_t ret = fread(mb_buff, 1, 8, pfile);
	if (ret != 8)
	{
		fprintf(stderr, "Read error: expected 8-byte PNG signature from %s (got %zu).\n", pngPath, ret);
		exit(1);
	}

	// expected magic bytes for a png file
	const uint8_t expected_bytes[8] = {
		0x89, 0x50, 0x4E, 0x47,
		0x0D, 0x0A, 0x1A, 0x0A};

	// check each 8 bytes
	for (uint32_t i = 0; i < 8; i++)
	{
		if (mb_buff[i] != expected_bytes[i])
		{
			fprintf(stderr, "Format error: invalid PNG signature byte %u (got 0x%X, expected 0x%X).\n", i, mb_buff[i], expected_bytes[i]);
			exit(1);
		}
	}

	// After Magic Byte, expect IHDR chunk
	// Each chunk has: Length (4 byte), Type (IHDR, IDAT, IEND), Data: (Length) Bytes, CRC (Cyclic Redundancy Check, type + data): 4 Bytes

	uint8_t length[4] = {0};
	uint8_t type[5] = {0};
	uint8_t crc[4] = {0};
	uint32_t WIDTH = 0;
	uint32_t HEIGHT = 0;
	uint32_t BIT_DEPTH = 0;
	uint32_t COLOR_TYPE = 0;
	uint32_t COMPRESSION = 0;
	uint32_t FILTER = 0;
	uint32_t INTERLACE = 0;
	uint8_t *idat = NULL;
	uint64_t idat_len = 0;

	// Read chunks until IEND, collecting IDAT data.
	while (1)
	{
		size_t length_ret = fread(length, 1, 4, pfile);
		if (length_ret != 4)
		{
			fprintf(stderr, "Read error: failed to read chunk length (expected 4 bytes, got %zu).\n", length_ret);
			free(idat);
			exit(1);
		}

		size_t type_ret = fread(type, 1, 4, pfile);
		if (type_ret != 4)
		{
			fprintf(stderr, "Read error: failed to read chunk type (expected 4 bytes, got %zu).\n", type_ret);
			free(idat);
			exit(1);
		}

		uint32_t len = buffer_to_int(length, 0);
		uint8_t *data = malloc(len);
		if (data == NULL)
		{
			fprintf(stderr, "Memory error: unable to allocate %u bytes for chunk data.\n", len);
			free(idat);
			exit(1);
		}
		size_t data_ret = fread(data, 1, len, pfile);
		if (data_ret != len)
		{
			fprintf(stderr, "Read error: failed to read chunk data (expected %u bytes, got %zu).\n", len, data_ret);
			free(data);
			free(idat);
			exit(1);
		}

		size_t crc_ret = fread(crc, 1, 4, pfile);
		if (crc_ret != 4)
		{
			fprintf(stderr, "Read error: failed to read chunk CRC (expected 4 bytes, got %zu).\n", crc_ret);
			free(data);
			free(idat);
			exit(1);
		}

		uint32_t crc_int = buffer_to_int(crc, 0);

		uLong crc_calc = crc32(0L, Z_NULL, 0);
		crc_calc = crc32(crc_calc, type, 4);
		if (len > 0)
			crc_calc = crc32(crc_calc, data, len);
		if (crc_calc != crc_int)
		{
			fprintf(stderr, "Integrity error: CRC mismatch for chunk %s.\n", (char *)type);
			free(data);
			free(idat);
			exit(1);
		}

		if (strcmp((char *)type, "IEND") == 0)
		{
			printf("REACHED END OF PNG\n");
			free(data);
			break;
		}
		else if (strcmp((char *)type, "IHDR") == 0)
		{
			if (len != 13)
			{
				fprintf(stderr, "Format error: IHDR length must be 13 bytes (got %u).\n", len);
				free(data);
				free(idat);
				exit(1);
			}

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
				   "\nINTERLACE: %d;\n",
				   WIDTH,
				   HEIGHT, BIT_DEPTH,
				   COLOR_TYPE, COMPRESSION, FILTER, INTERLACE);

			if (!(COLOR_TYPE == 6 &&
				  BIT_DEPTH == 8 && COMPRESSION == 0 &&
				  FILTER == 0 && INTERLACE == 0))
			{
				fprintf(stderr, "Format error: unsupported PNG (color=%u, depth=%u, comp=%u, filter=%u, interlace=%u).\n",
						COLOR_TYPE, BIT_DEPTH, COMPRESSION, FILTER, INTERLACE);
				free(data);
				free(idat);
				exit(1);
			}
		}
		else if (strcmp((char *)type, "IDAT") == 0)
		{
			// concat all the idat chunk data into one buffer
			uint8_t *new_idat = realloc(idat, idat_len + len);
			if (new_idat == NULL)
			{
				fprintf(stderr, "Memory error: unable to grow IDAT buffer to %llu bytes.\n",
						(unsigned long long)(idat_len + len));
				free(data);
				free(idat);
				exit(1);
			}
			idat = new_idat;
			memcpy(idat + idat_len, data, len);
			idat_len += len;
		}
		else if (islower((char)type[0]) || strcmp((char *)type, "PLTE") == 0)
		{
			// Ancillary chunks can be skipped for this viewer.
			free(data);
			continue;
		}
		else
		{
			fprintf(stderr, "Format error: unsupported critical chunk type %s.\n", (char *)type);
			free(data);
			free(idat);
			exit(1);
		}
		free(data);
	}
	fclose(pfile);

	// inflate the concat'd idat with zlib
	uint32_t row_bytes = WIDTH * 4;
	uint32_t expected = HEIGHT * (1 + row_bytes);
	uint8_t *inflated = malloc(expected);
	if (inflated == NULL)
	{
		fprintf(stderr, "Memory error: unable to allocate %u bytes for zlib output.\n", expected);
		free(idat);
		exit(1);
	}

	z_stream zs;
	memset(&zs, 0, sizeof(zs));
	if (inflateInit(&zs) != Z_OK)
	{
		fprintf(stderr, "Zlib error: inflateInit failed.\n");
		free(inflated);
		free(idat);
		exit(1);
	}

	zs.next_in = idat;
	zs.avail_in = idat_len;
	zs.next_out = inflated;
	zs.avail_out = expected;

	int r = inflate(&zs, Z_FINISH);
	if (r != Z_STREAM_END)
	{
		fprintf(stderr, "Zlib error: inflate failed (code %d).\n", r);
		inflateEnd(&zs);
		free(inflated);
		free(idat);
		exit(r);
	}
	if (zs.total_out != expected)
	{
		fprintf(stderr, "Zlib error: unexpected output size (got %lu, expected %u).\n",
				(unsigned long)zs.total_out, expected);
		inflateEnd(&zs);
		free(inflated);
		free(idat);
		exit(1);
	}

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

	uint8_t *pixels = malloc(WIDTH * HEIGHT * 4);
	if (pixels == NULL)
	{
		fprintf(stderr, "Memory error: unable to allocate %u bytes for pixel buffer.\n", WIDTH * HEIGHT * 4);
		free(inflated);
		free(idat);
		exit(1);
	}
	unsigned int bpp = 4; // bytes per pixel
	uint8_t *prev = NULL; // stores previous row

	for (unsigned int row = 0; row < HEIGHT; row++)
	{
		uint8_t *row_s = inflated + (size_t)(row) * (1 + row_bytes);
		uint8_t filter_type = row_s[0];
		uint8_t *src = row_s + 1;
		uint8_t *dst = pixels + (size_t)(row)*row_bytes; // since we don't need the filter byte

		switch ((int)filter_type)
		{
		case 0:
			memcpy(dst, src, row_bytes);
			break;
		case 1: // Sub
			for (unsigned int i = 0; i < row_bytes; i++)
			{
				uint8_t left = (i >= bpp) ? dst[i - bpp] : 0;
				dst[i] = (src[i] + left);
			}
			break;
		case 2: // Up
			for (unsigned int i = 0; i < row_bytes; i++)
			{
				uint8_t up = prev ? prev[i] : 0;
				dst[i] = (src[i] + up);
			}
			break;
		case 3: // Average
			for (unsigned int i = 0; i < row_bytes; i++)
			{
				uint8_t left = (i >= bpp) ? dst[i - bpp] : 0;
				uint8_t up = prev ? prev[i] : 0;
				dst[i] = (uint8_t)(src[i] + (uint8_t)(((int)left + (int)up) / 2));
			}
			break;
		case 4: // Paeth
			for (unsigned int i = 0; i < row_bytes; i++)
			{
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

	// Create SDL surfaces from raw RGBA pixels.
	SDL_Window *pwindow = SDL_CreateWindow("pngViewer", SDL_WINDOWPOS_CENTERED, SDL_WINDOWPOS_CENTERED, WIDTH, HEIGHT, 0);
	SDL_Surface *psurface = SDL_GetWindowSurface(pwindow);

	SDL_Surface *img = SDL_CreateRGBSurfaceWithFormatFrom(pixels, WIDTH, HEIGHT, 32, WIDTH * 4, SDL_PIXELFORMAT_RGBA32);

	if (img == NULL)
	{
		fprintf(stderr, "SDL error: failed to create surface from pixel buffer.\n");
		free(pixels);
		free(inflated);
		free(idat);
		exit(1);
	}

	SDL_Surface *img_conv = SDL_ConvertSurface(img, psurface->format, 0);
	if (img_conv == NULL)
	{
		fprintf(stderr, "SDL error: failed to convert surface to window format.\n");
		SDL_FreeSurface(img);
		free(pixels);
		free(inflated);
		free(idat);
		exit(1);
	}

	SDL_BlitSurface(img_conv, NULL, psurface, NULL);
	SDL_UpdateWindowSurface(pwindow);

	SDL_Event e;
	int running = 1;

	while (running)
	{
		while (SDL_PollEvent(&e))
		{
			if (e.type == SDL_QUIT)
				running = 0;
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
