#ifndef SHIFT_ROWS_H
#define SHIFT_ROWS_H

#include "aes.h"

void ShiftRows(AESState state);
void InvShiftRows(AESState state);

#endif //SHIFT_ROWS_H