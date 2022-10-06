#include "threads/fixed-point.h"
#include <stdint.h>

int int_to_fp(int i) {
  return i * F;
}

int fp_to_int (int fp) {
  return fp / F;
}

int fp_to_int_round(int fp) {
  return (fp >= 0) ? (fp + F / 2) / F : (fp - F / 2) / F;
}

int add_fp(int x, int y) {
  return x + y;
}

int add_fp_int(int fp, int i) {
  return fp + i * F;
}

int sub_fp(int x, int y) {
  return x - y;
}

int sub_mixed (int fp, int i) {
  return fp - i * F;
}

int mul_fp(int x, int y) {
  return ((int64_t) x) * y / F;
}

int mul_fp_int(int fp, int i) {
  return fp * i;
}

int div_fp(int x, int y) {
  return ((int64_t) x) * F / y;
}

int div_fp_int(int fp, int i) {
  return fp / i;
}