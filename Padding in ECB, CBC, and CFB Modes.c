#include <stdio.h>
#include <stdint.h>
#include <string.h>
#define STATE_SIZE 1600
#define RATE_SIZE 1024
#define CAPACITY_SIZE (STATE_SIZE - RATE_SIZE)
#define NUM_LANES 25
#define LANE_SIZE 64
uint64_t state[NUM_LANES];
void initialize_state() {
    int i;
    for (i = 0; i < NUM_LANES; i++) {
        state[i] = 0;
    }
    for (i = 0; i < (RATE_SIZE / LANE_SIZE); i++) {
        state[i] = 1;
    }
}
int capacity_is_nonzero() {
	int i;
    for (i = RATE_SIZE / LANE_SIZE; i < NUM_LANES; i++) {
        if (state[i] == 0) {
            return 0;
        }
    }
    return 1;
}
void simulate_sha3() {
	int i;
    int iterations = 0;
    while (!capacity_is_nonzero()) {
        for (i = 0; i < (RATE_SIZE / LANE_SIZE); i++) {
            state[i + (RATE_SIZE / LANE_SIZE)] ^= state[i];
        }
        iterations++;
    }
    printf("Iterations until all capacity lanes have non-zero bits: %d\n", iterations);
}
int main() {
    initialize_state();
    simulate_sha3();
    return 0;
}
