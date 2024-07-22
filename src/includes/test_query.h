#pragma once

#include "external_prod.h"
#include "pir.h"
#include "server.h"

#define DB_SZ       1 << 15
#define NUM_DIM     8
#define NUM_ENTRIES 1 << 15
#define ENTRY_SZ    12000
#define GSW_L       9
#define GSW_L_KEY   9

void run_query_test();

