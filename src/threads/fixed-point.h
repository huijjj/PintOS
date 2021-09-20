#ifndef FIXED_POINT_H
#define FIXED_POINT_H

#define F (1 << 14)

// conversion
int int_to_fp(int i);
int fp_to_int(int fp);
int fp_to_int_round(int fp);

// arithmetic
int add_fp(int x, int y);
int add_fp_int(int fp, int i);
int sub_fp(int x, int y);
int sub_fp_int(int fp, int i);
int mult_fp(int x, int y);
int mult_fp_int(int fp, int i);
int div_fp(int x, int y);
int div_fp_int(int fp, int i);

#endif