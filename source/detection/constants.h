#pragma once

#include <stdint.h>


/* ---------------- Address selection Mode---------------- */
// Uncomment exactly ONE:
// #define USE_FIXED_START_ADDR
#define USE_PROC_MAPS

/* ---------------- Fixed Address + Size---------------- */
#define START_ADDR 0x7ffff71df000
#define SIZE 3072

/* ---------------- Cache timing thresholds (cycles) ---------------- */
/* Measured as delta = rdtsc(); maccess(addr); rdtsc() - delta. */
/* These values include rdtsc measurement overhead. */
#define THR_L1   100
#define THR_L3   150
#define THR_MISS 500
