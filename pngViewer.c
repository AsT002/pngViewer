#include <stdio.h>
#include <stdlib.h>
#include <SDL2/SDL.h>
#include <sys/stat.h>


//  default size of the window
#define WIDTH 600
#define HEIGHT 600


int buffer_to_int(unsigned char *buf) {

	return ((int)buf[0]<<24)|((int)buf[1]<<16)|((int)buf[2]<<8)|((int)buf[3]<<0);
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
	

	while (1) {
		printf("Chunk %d\n", chunks);
		size_t length_ret = fread(length, 1, 4, pfile);
		if (length_ret != 4) {  printf("fread error (length)\n"); exit(1);  }

		size_t type_ret = fread(type, 1, 4, pfile);
		if (type_ret != 4) {  printf("fread error (type)\n"); exit(1);  }
		
		int len = buffer_to_int(length);
		unsigned char data[len];
		size_t data_ret = fread(data, 1, len, pfile);
		if (data_ret != len) {  printf("fread error (data)\n"); exit(1);  }

		size_t crc_ret = fread(crc, 1, 4, pfile);
		if (crc_ret != 4) {  printf("fread error (crc)\n"); exit(1);  }
	
		if (strcmp((char *)type, "IEND") == 0) {
			printf("Reached end\n");
			break;
		}
		
	
	}

	SDL_Window *pwindow = SDL_CreateWindow("pngViewer", SDL_WINDOWPOS_CENTERED, SDL_WINDOWPOS_CENTERED, WIDTH, HEIGHT, 0);

	SDL_Delay(5000);
}
