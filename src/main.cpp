#include "pir.h"
#include "server.h"
#include "tests.h"
#include "test_query.h"
#include <chrono>
#include <iostream>

int main() {
  // run_tests(); // normal tests for Onion PIR
  run_query_test(); // tests and experiments for query related stuff
  return 0;
}