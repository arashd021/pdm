#pragma once

#include <stdint.h>


/* ---------------- Address selection Mode---------------- */
// Uncomment exactly ONE:
// #define USE_FIXED_START_ADDR
#define USE_PROC_MAPS

/* ---------------- Fixed Address + Size---------------- */
#define START_ADDR 0x7ffff6fdf000
#define SIZE 3072

/* ---------------- Cache timing thresholds (cycles) ---------------- */
#define THR_L1   500
#define THR_L3   700
#define THR_MISS 1000