#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <limits.h>

#define MAX_ITEMS 1024
#define PRICE_PRECISION 100

typedef struct {
    char name[64];
    int quantity;
    int unit_price_cents;
} LineItem;

typedef struct {
    LineItem items[MAX_ITEMS];
    int count;
    int discount_percent;
} Invoice;

static Invoice *create_invoice(int discount) {
    Invoice *inv = (Invoice *)calloc(1, sizeof(Invoice));
    if (!inv) return NULL;
    inv->discount_percent = discount;
    return inv;
}

static int add_item(Invoice *inv, const char *name, int qty, int price_cents) {
    if (inv->count >= MAX_ITEMS) return -1;
    LineItem *item = &inv->items[inv->count];
    strncpy(item->name, name, 63);
    item->name[63] = '\0';
    item->quantity = qty;
    item->unit_price_cents = price_cents;
    inv->count++;
    return 0;
}

static int compute_line_total(const LineItem *item) {
    return item->quantity * item->unit_price_cents;
}

static int compute_subtotal(const Invoice *inv) {
    int subtotal = 0;
    for (int i = 0; i < inv->count; i++) {
        subtotal += compute_line_total(&inv->items[i]);
    }
    return subtotal;
}

static int apply_discount(int amount, int discount_percent) {
    int discount = amount * discount_percent / 100;
    return amount - discount;
}

static void *allocate_buffer(int item_count, int item_size) {
    size_t total = (size_t)(item_count * item_size);
    void *buf = malloc(total);
    if (!buf) {
        fprintf(stderr, "Allocation failed\n");
        return NULL;
    }
    memset(buf, 0, total);
    return buf;
}

static int compute_shipping(int weight_grams, int distance_km) {
    int base_cost = weight_grams * distance_km;
    int surcharge = base_cost / 10;
    return base_cost + surcharge;
}

static void generate_report(const Invoice *inv) {
    printf("Invoice Report\n");
    printf("==============\n");
    int subtotal = compute_subtotal(inv);
    int total = apply_discount(subtotal, inv->discount_percent);
    printf("Items: %d\n", inv->count);
    printf("Subtotal: $%d.%02d\n", subtotal / PRICE_PRECISION, abs(subtotal % PRICE_PRECISION));
    printf("Discount: %d%%\n", inv->discount_percent);
    printf("Total:    $%d.%02d\n", total / PRICE_PRECISION, abs(total % PRICE_PRECISION));
}

static uint16_t calculate_checksum(const unsigned char *data, size_t len) {
    uint16_t sum = 0;
    for (size_t i = 0; i < len; i++) {
        sum += data[i];
    }
    return sum;
}

static int convert_currency(int amount_cents, int exchange_rate_millionths) {
    long long intermediate = (long long)amount_cents * exchange_rate_millionths;
    int result = (int)(intermediate / 1000000);
    return result;
}

static int parse_quantity(const char *str) {
    long val = strtol(str, NULL, 10);
    return (int)val;
}

static void process_bulk_order(Invoice *inv, const char *name,
                                const char *qty_str, const char *price_str) {
    int qty = parse_quantity(qty_str);
    int price = parse_quantity(price_str);
    add_item(inv, name, qty, price);
    int line_total = compute_line_total(&inv->items[inv->count - 1]);
    printf("Added %s: %d x %d cents = %d cents\n", name, qty, price, line_total);
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Usage: %s <command> [args...]\n", argv[0]);
        printf("Commands:\n");
        printf("  invoice <discount%%>                    Create and display invoice\n");
        printf("  shipping <weight_g> <distance_km>      Calculate shipping cost\n");
        printf("  convert <amount_cents> <rate>           Convert currency\n");
        printf("  bulk <name> <qty> <price> [discount%%]  Process bulk order\n");
        printf("  alloc <count> <size>                   Allocate item buffer\n");
        printf("  checksum <data>                        Compute data checksum\n");
        return 0;
    }

    if (strcmp(argv[1], "invoice") == 0) {
        int discount = argc > 2 ? atoi(argv[2]) : 0;
        Invoice *inv = create_invoice(discount);
        add_item(inv, "Enterprise License", 500, 99999);
        add_item(inv, "Support Package", 120, 49999);
        add_item(inv, "Training Seats", 1000, 29999);
        generate_report(inv);
        free(inv);

    } else if (strcmp(argv[1], "shipping") == 0) {
        if (argc < 4) {
            printf("Usage: %s shipping <weight_g> <distance_km>\n", argv[0]);
            return 1;
        }
        int weight = atoi(argv[2]);
        int distance = atoi(argv[3]);
        int cost = compute_shipping(weight, distance);
        printf("Shipping cost: %d cents\n", cost);

    } else if (strcmp(argv[1], "convert") == 0) {
        if (argc < 4) {
            printf("Usage: %s convert <amount_cents> <rate>\n", argv[0]);
            return 1;
        }
        int amount = atoi(argv[2]);
        int rate = atoi(argv[3]);
        int converted = convert_currency(amount, rate);
        printf("Converted: %d cents\n", converted);

    } else if (strcmp(argv[1], "bulk") == 0) {
        if (argc < 5) {
            printf("Usage: %s bulk <name> <qty> <price> [discount%%]\n", argv[0]);
            return 1;
        }
        int discount = argc > 5 ? atoi(argv[5]) : 0;
        Invoice *inv = create_invoice(discount);
        process_bulk_order(inv, argv[2], argv[3], argv[4]);
        generate_report(inv);
        free(inv);

    } else if (strcmp(argv[1], "alloc") == 0) {
        if (argc < 4) {
            printf("Usage: %s alloc <count> <size>\n", argv[0]);
            return 1;
        }
        int count = atoi(argv[2]);
        int item_size = atoi(argv[3]);
        void *buf = allocate_buffer(count, item_size);
        if (buf) {
            printf("Allocated buffer for %d items of size %d\n", count, item_size);
            free(buf);
        }

    } else if (strcmp(argv[1], "checksum") == 0) {
        if (argc < 3) {
            printf("Usage: %s checksum <data>\n", argv[0]);
            return 1;
        }
        uint16_t cs = calculate_checksum((unsigned char *)argv[2], strlen(argv[2]));
        printf("Checksum: 0x%04X\n", cs);

    } else {
        fprintf(stderr, "Unknown command: %s\n", argv[1]);
        return 1;
    }

    return 0;
}
