#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>
#include <signal.h>

#define RandomNumberInInterval(min,max) rand()%(max-min+1)+min
// #########################################################################

void flip_bits(char *data, int filelen, float flip_percent) {

  int num_of_flips = filelen * flip_percent;
  int *chosen_indexes = malloc(num_of_flips * sizeof(int));

  for (size_t i=0; i < num_of_flips; i++)
    chosen_indexes[i] = rand() % filelen;

  // Iterate selecting indexes until we've hit our num_of_flips number
  for (size_t i = 0; i < num_of_flips; i++) {

	int index 			  = chosen_indexes[i];
	unsigned char current = data[index];
	int decimal 		  = ((int)current & 0xff);

	int bit_to_flip 	  = rand() % 8;
	
	decimal ^= 1 << bit_to_flip;
	decimal &= 0xff;
	
	data[index] = (unsigned char)decimal;
  }

  return;
}

void insert_magic(unsigned char *data, long filelen, float mutatation_rate) {
	unsigned int *magic_index, picked_magic[2], picked_index;
	unsigned int magic_vals[11][2] = {
		{1, 255},
		{1, 255},
		{1, 127},
		{1, 0},
		{2, 255},
		{2, 0},
		{4, 255},
		{4, 0},
		{4, 128},
		{4, 64},
		{4, 127},
	};
	int num_of_flips = filelen * mutatation_rate;
	int flipCounter=0;

	do
	{
		magic_index = (int*)&magic_vals[rand() % 11];
		picked_magic[0] = magic_vals[*magic_index][0];
		picked_magic[1] = magic_vals[*magic_index][1];
		picked_index = RandomNumberInInterval(6,filelen);

		// here we are hardcoding all the byte overwrites for all of the tuples that begin (1, )
		if (picked_magic[0] == 1) {
			if (picked_magic[1] == 255)			    // 0xFF
				data[picked_index] = 0xFF;
			else if (picked_magic[1] == 127)		// 0x7F
				data[picked_index] = 0x7F;
			else if (picked_magic[1] == 0)			// 0x00
				data[picked_index] = 0x00;
		}
		// here we are hardcoding all the byte overwrites for all of the tuples that begin (2, )
		else if (picked_magic[0] == 2) {
			if (picked_magic[1] == 255)	{	      // 0xFFFF
				data[picked_index]     = 0xFF;
				data[picked_index + 1] = 0xFF;
			}	
			else if (picked_magic[1] == 0) {    // 0x0000
				data[picked_index]     = 0x00;
				data[picked_index + 1] = 0x00;
			}			
		}
		// here we are hardcoding all of the byte overwrites for all of the tuples that being (4, )
		else if (picked_magic[0]   == 4) {
			if (picked_magic[1]      == 255) {  // 0xFFFFFFFF
				data[picked_index]     = 0xFF;
				data[picked_index + 1] = 0xFF;
				data[picked_index + 2] = 0xFF;
				data[picked_index + 3] = 0xFF;
			}
			else if (picked_magic[1] == 0) {    // 0x00000000
				data[picked_index]     = 0x00;
				data[picked_index + 1] = 0x00;
				data[picked_index + 2] = 0x00;
				data[picked_index + 3] = 0x00;
			}			
			else if (picked_magic[1] == 128) {  // 0x80000000
				data[picked_index]     = 0x80;
				data[picked_index + 1] = 0x00;
				data[picked_index + 2] = 0x00;
				data[picked_index + 3] = 0x00;
			}
			else if (picked_magic[1] == 64)	{   // 0x40000000
				data[picked_index]     =  0x40;
				data[picked_index + 1] =  0x00;
				data[picked_index + 2] =  0x00;
				data[picked_index + 3] =  0x00;
			}
			else if (picked_magic[1] == 127) {  // 0x7FFFFFFF
				data[picked_index]     = 0x7F;
				data[picked_index + 1] = 0xFF;
				data[picked_index + 2] = 0xFF;
				data[picked_index + 3] = 0xFF;
			}		
		}
		flipCounter++;
  } while(flipCounter < num_of_flips);

  return;
}