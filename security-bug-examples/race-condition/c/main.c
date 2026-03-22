#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>

typedef struct {
    char owner[64];
    long balance;
} BankAccount;

typedef struct {
    BankAccount *alice;
    BankAccount *bob;
    int iterations;
} TransferArgs;

void *do_transfers(void *arg) {
    TransferArgs *ta = (TransferArgs *)arg;
    for (int i = 0; i < ta->iterations; i++) {
        long bal_a = ta->alice->balance;
        sched_yield();
        ta->alice->balance = bal_a - 100;
        ta->bob->balance += 100;

        long bal_b = ta->bob->balance;
        sched_yield();
        ta->bob->balance = bal_b - 100;
        ta->alice->balance += 100;
    }
    return NULL;
}

static int ticket_available = 0;
static int ticket_sold = 0;

typedef struct {
    int per_thread;
} TicketArgs;

void *do_ticket_booking(void *arg) {
    TicketArgs *ta = (TicketArgs *)arg;
    for (int i = 0; i < ta->per_thread; i++) {
        if (ticket_available > 0) {
            sched_yield();
            ticket_available--;
            ticket_sold++;
        }
    }
    return NULL;
}

static long shared_counter = 0;

typedef struct {
    int increments;
} CounterArgs;

void *do_increment(void *arg) {
    CounterArgs *ca = (CounterArgs *)arg;
    for (int i = 0; i < ca->increments; i++) {
        long current = shared_counter;
        sched_yield();
        shared_counter = current + 1;
    }
    return NULL;
}

static int inventory_stock = 0;
static int order_count = 0;

typedef struct {
    int per_thread;
} OrderArgs;

void *do_place_orders(void *arg) {
    OrderArgs *oa = (OrderArgs *)arg;
    for (int i = 0; i < oa->per_thread; i++) {
        int stock = inventory_stock;
        if (stock > 0) {
            sched_yield();
            inventory_stock = stock - 1;
            order_count++;
        }
    }
    return NULL;
}

void *do_restock(void *arg) {
    OrderArgs *oa = (OrderArgs *)arg;
    for (int i = 0; i < oa->per_thread; i++) {
        int current = inventory_stock;
        sched_yield();
        inventory_stock = current + 1;
    }
    return NULL;
}

static char *config_data = NULL;
static int config_ready = 0;

void *do_init_config(void *arg) {
    (void)arg;
    if (!config_ready) {
        sched_yield();
        config_data = (char *)malloc(256);
        if (config_data) {
            strcpy(config_data, "initialized");
        }
        config_ready = 1;
    }
    return NULL;
}

void run_bank_simulation(int num_threads, int iterations) {
    BankAccount alice = { .owner = "Alice", .balance = 10000 };
    BankAccount bob = { .owner = "Bob", .balance = 10000 };
    long initial_total = alice.balance + bob.balance;

    TransferArgs ta = { .alice = &alice, .bob = &bob, .iterations = iterations };
    pthread_t *threads = malloc(sizeof(pthread_t) * num_threads);

    for (int i = 0; i < num_threads; i++) {
        pthread_create(&threads[i], NULL, do_transfers, &ta);
    }
    for (int i = 0; i < num_threads; i++) {
        pthread_join(threads[i], NULL);
    }

    printf("Bank Simulation (%d threads, %d iterations)\n", num_threads, iterations);
    printf("  Initial total: %ld\n", initial_total);
    printf("  Final total:   %ld\n", alice.balance + bob.balance);
    printf("  Alice balance: %ld\n", alice.balance);
    printf("  Bob balance:   %ld\n", bob.balance);
    free(threads);
}

void run_ticket_simulation(int num_threads, int total_tickets) {
    ticket_available = total_tickets;
    ticket_sold = 0;
    int per_thread = total_tickets / num_threads;

    TicketArgs ta = { .per_thread = per_thread };
    pthread_t *threads = malloc(sizeof(pthread_t) * num_threads);

    for (int i = 0; i < num_threads; i++) {
        pthread_create(&threads[i], NULL, do_ticket_booking, &ta);
    }
    for (int i = 0; i < num_threads; i++) {
        pthread_join(threads[i], NULL);
    }

    printf("Ticket Simulation (%d threads, %d tickets)\n", num_threads, total_tickets);
    printf("  Available: %d\n", ticket_available);
    printf("  Sold:      %d\n", ticket_sold);
    printf("  Total:     %d\n", ticket_available + ticket_sold);
    free(threads);
}

void run_counter_simulation(int num_threads, int increments) {
    shared_counter = 0;

    CounterArgs ca = { .increments = increments };
    pthread_t *threads = malloc(sizeof(pthread_t) * num_threads);

    for (int i = 0; i < num_threads; i++) {
        pthread_create(&threads[i], NULL, do_increment, &ca);
    }
    for (int i = 0; i < num_threads; i++) {
        pthread_join(threads[i], NULL);
    }

    long expected = (long)num_threads * increments;
    printf("Counter Simulation (%d threads, %d increments each)\n", num_threads, increments);
    printf("  Expected: %ld\n", expected);
    printf("  Actual:   %ld\n", shared_counter);
    free(threads);
}

void run_inventory_simulation(int num_threads, int quantity) {
    inventory_stock = quantity;
    order_count = 0;
    int per_thread = quantity / num_threads;

    OrderArgs oa = { .per_thread = per_thread };
    pthread_t *threads = malloc(sizeof(pthread_t) * (num_threads + 1));

    for (int i = 0; i < num_threads; i++) {
        pthread_create(&threads[i], NULL, do_place_orders, &oa);
    }
    OrderArgs restock_args = { .per_thread = per_thread / 2 };
    pthread_create(&threads[num_threads], NULL, do_restock, &restock_args);

    for (int i = 0; i <= num_threads; i++) {
        pthread_join(threads[i], NULL);
    }

    printf("Inventory Simulation (%d threads)\n", num_threads);
    printf("  Initial stock: %d\n", quantity);
    printf("  Final stock:   %d\n", inventory_stock);
    printf("  Orders:        %d\n", order_count);
    free(threads);
}

void run_singleton_simulation(int num_threads) {
    config_data = NULL;
    config_ready = 0;

    pthread_t *threads = malloc(sizeof(pthread_t) * num_threads);
    for (int i = 0; i < num_threads; i++) {
        pthread_create(&threads[i], NULL, do_init_config, NULL);
    }
    for (int i = 0; i < num_threads; i++) {
        pthread_join(threads[i], NULL);
    }

    printf("Singleton Simulation (%d threads)\n", num_threads);
    printf("  Config ready: %d\n", config_ready);
    printf("  Config data:  %s\n", config_data ? config_data : "(null)");
    free(config_data);
    free(threads);
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Usage: %s <command> [args...]\n", argv[0]);
        printf("Commands:\n");
        printf("  bank <threads> <iterations>     Bank transfer simulation\n");
        printf("  tickets <threads> <total>        Ticket booking simulation\n");
        printf("  counter <threads> <increments>   Shared counter simulation\n");
        printf("  inventory <threads> <quantity>   Inventory simulation\n");
        printf("  singleton <threads>              Config singleton simulation\n");
        return 0;
    }

    if (strcmp(argv[1], "bank") == 0) {
        int t = argc > 2 ? atoi(argv[2]) : 4;
        int i = argc > 3 ? atoi(argv[3]) : 100;
        run_bank_simulation(t, i);
    } else if (strcmp(argv[1], "tickets") == 0) {
        int t = argc > 2 ? atoi(argv[2]) : 4;
        int n = argc > 3 ? atoi(argv[3]) : 100;
        run_ticket_simulation(t, n);
    } else if (strcmp(argv[1], "counter") == 0) {
        int t = argc > 2 ? atoi(argv[2]) : 4;
        int i = argc > 3 ? atoi(argv[3]) : 1000;
        run_counter_simulation(t, i);
    } else if (strcmp(argv[1], "inventory") == 0) {
        int t = argc > 2 ? atoi(argv[2]) : 4;
        int q = argc > 3 ? atoi(argv[3]) : 200;
        run_inventory_simulation(t, q);
    } else if (strcmp(argv[1], "singleton") == 0) {
        int t = argc > 2 ? atoi(argv[2]) : 8;
        run_singleton_simulation(t);
    } else {
        fprintf(stderr, "Unknown command: %s\n", argv[1]);
        return 1;
    }

    return 0;
}
