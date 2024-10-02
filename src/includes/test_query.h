#pragma once

#include "pir.h"
#include "client.h"
#include "server.h"

#define DB_SZ       1 << 15
#define NUM_DIM     8
#define NUM_ENTRIES 1 << 15
#define ENTRY_SZ    12000
#define GSW_L       9
#define GSW_L_KEY   9

void run_query_test();

class PirTest {
  public: 
    // prepare the test data. Initialize the server database if init_db is true
    std::unique_ptr<PirServer> prepare_server(bool init_db, PirParams& pir_params, PirClient& client, const int client_id);

    // only test on the client generate query and server expand query
    void gen_and_expand();

    // An example of "enc then add" trick in generate_query
    void enc_then_add();

    // Testing the noise budget before and after the query expansion
    // void noise_budget_test();
};
