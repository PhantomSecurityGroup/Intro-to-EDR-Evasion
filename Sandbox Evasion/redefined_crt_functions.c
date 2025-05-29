#include "redefined_crt_functions.h"

int toupper(int ch)
{
    if (ch >= 'a' && ch <= 'z')
        ch -= 32;
    return ch;
}