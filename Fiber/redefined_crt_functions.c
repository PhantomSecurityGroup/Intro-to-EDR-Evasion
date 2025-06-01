#include "redefined_crt_functions.h"

static unsigned int seed = 0;

int toupper(int ch)
{
    if (ch >= 'a' && ch <= 'z')
        ch -= 32;
    return ch;
}

int compile_time_seed(void)
{
	return '0' * -40271 +
		__TIME__[7] * 1 +
		__TIME__[6] * 10 +
		__TIME__[4] * 60 +
		__TIME__[3] * 600 +
		__TIME__[1] * 3600 +
		__TIME__[0] * 36000;
}

void srand(unsigned int s) {
	seed = s;
}

int rand(void) {
	seed = (1103515245 * seed + 12345) % (2 << 31);
	return seed;
}
