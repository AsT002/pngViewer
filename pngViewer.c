#include <stdio.h>
#include <stdlib.h>
#include <SDL2/SDL.h>
#include <sys/stat.h>
#include <zlib.h>

uint32_t buffer_to_int(unsigned char *buf, int s) {
	return ((int)buf[s+0]<<24)|((int)buf[s+1]<<16)|((int)buf[s+2]<<8)|((int)buf[s+3]<<0);
}


int main(int argc, char** argv) {
	if (argc < 2) {
		printf("Please include the path to the png file in the args.\n");
		exit(1);
	}

	char* pngPath = argv[1];
		
	struct stat buffer;
	if (stat (pngPath, &buffer) != 0) {
		printf("Couldn't find the PNG file specified in the args.\n");
		exit(1);
	}	
		
	FILE *pfile = fopen(pngPath, "rb");
	if (!pfile) {
		printf("fopen ran into an issue while opening the png file.\n");
		exit(1);	
	}
	
	unsigned char mb_buff[8];
	size_t ret = fread(mb_buff, 1, 8, pfile);
	if (ret != 8) {
		printf("Error reading the PNG file. (MB)\n");
		exit(1);
	}

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

	if (!is_png) {
		printf("The file given is not a PNG file. Magic bytes do not match.\n");
		exit(1);
	}
	
	
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

	while (1) {
		size_t length_ret = fread(length, 1, 4, pfile);
		if (length_ret != 4) {  printf("fread error (length)\n"); exit(1);  }

		size_t type_ret = fread(type, 1, 4, pfile);
		if (type_ret != 4) {  printf("fread error (type)\n"); exit(1);  }
		
		uint32_t len = buffer_to_int(length, 0);
		unsigned char* data = (unsigned char *)malloc(len);
		size_t data_ret = fread(data, 1, len, pfile);
		if (data_ret != len) {  printf("fread error (data)\n"); exit(1);  }

		size_t crc_ret = fread(crc, 1, 4, pfile);
		if (crc_ret != 4) {  printf("fread error (crc)\n"); exit(1);  }
		uint32_t crc_int = buffer_to_int(crc, 0);

		uLong crc_calc = crc32(0L, Z_NULL, 0);
		crc_calc = crc32(crc_calc, type, 4);
		if (len > 0) crc_calc = crc32(crc_calc, data, len);

		if (crc_calc != crc_int) {
			printf("CRC mismatch!\n");
			exit(1);
		}
	
		if (strcmp((char *)type, "IEND") == 0) {
			printf("REACHED END OF PNG\n");
			break;
		} else if (strcmp((char *)type, "IHDR") == 0) {
			if (len != 13) {
				printf("Invalid header chunk\n");
				exit(1);
			}
			
			WIDTH = buffer_to_int(data, 0);
			HEIGHT = buffer_to_int(data, 4);	
			BIT_DEPTH = (0x0) | data[8];
			COLOR_TYPE = (0x0) | data[9];
			COMPRESSION = (0x0) | data[10];
			FILTER = (0x0) | data[11];
			INTERLACE = (0x0) | data[12];	
			printf("WIDTH: %d;\nHEIGHT: %d;\nBIT DEPTH: %d;\nCOLOR TYPE: %d;\nCOMPRESSION: %d;\nFILTER: %d;\nINTERLACE: %d;\n", WIDTH, HEIGHT, BIT_DEPTH, COLOR_TYPE, COMPRESSION, FILTER, INTERLACE);
		
			
			
		}
		
	
	}



	SDL_Window *pwindow = SDL_CreateWindow("pngViewer", SDL_WINDOWPOS_CENTERED, SDL_WINDOWPOS_CENTERED, WIDTH, HEIGHT, 0);

	SDL_Delay(5000);
}
