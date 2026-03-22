import sys
import threading
import time
import os
import json

class BankAccount:
    def __init__(self, owner, balance):
        self.owner = owner
        self.balance = balance
        self.transaction_log = []

    def get_balance(self):
        return self.balance

    def deposit(self, amount):
        current = self.balance
        time.sleep(0.001)
        self.balance = current + amount
        self.transaction_log.append({"type": "deposit", "amount": amount})

    def withdraw(self, amount):
        if self.balance >= amount:
            time.sleep(0.001)
            self.balance -= amount
            self.transaction_log.append({"type": "withdrawal", "amount": amount})
            return True
        return False

    def transfer_to(self, other, amount):
        if self.balance >= amount:
            time.sleep(0.001)
            self.balance -= amount
            other.balance += amount
            self.transaction_log.append({"type": "transfer_out", "amount": amount})
            other.transaction_log.append({"type": "transfer_in", "amount": amount})
            return True
        return False


class TicketPool:
    def __init__(self, total_tickets):
        self.available = total_tickets
        self.reservations = {}
        self.reservation_counter = 0

    def check_availability(self, count):
        return self.available >= count

    def reserve(self, customer, count):
        if self.check_availability(count):
            time.sleep(0.001)
            self.available -= count
            self.reservation_counter += 1
            rid = self.reservation_counter
            self.reservations[rid] = {"customer": customer, "count": count}
            return rid
        return None

    def cancel(self, reservation_id):
        if reservation_id in self.reservations:
            info = self.reservations[reservation_id]
            time.sleep(0.001)
            self.available += info["count"]
            del self.reservations[reservation_id]
            return True
        return False


class InventoryManager:
    def __init__(self):
        self.products = {}
        self.order_count = 0

    def add_product(self, name, quantity):
        self.products[name] = quantity

    def process_order(self, name, quantity):
        if name in self.products and self.products[name] >= quantity:
            time.sleep(0.001)
            self.products[name] -= quantity
            self.order_count += 1
            return self.order_count
        return None

    def restock(self, name, quantity):
        if name in self.products:
            current = self.products[name]
            time.sleep(0.001)
            self.products[name] = current + quantity


class ConfigCache:
    _instance = None
    _initialized = False

    def __new__(cls):
        if cls._instance is None:
            time.sleep(0.001)
            cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self):
        if not ConfigCache._initialized:
            time.sleep(0.001)
            self.settings = {}
            ConfigCache._initialized = True

    def set(self, key, value):
        self.settings[key] = value

    def get(self, key):
        return self.settings.get(key)


def file_based_counter(filepath):
    if os.path.exists(filepath):
        with open(filepath, "r") as f:
            count = int(f.read().strip())
    else:
        count = 0
    count += 1
    with open(filepath, "w") as f:
        f.write(str(count))
    return count


def run_bank_simulation(num_threads, iterations):
    account_a = BankAccount("Alice", 10000)
    account_b = BankAccount("Bob", 10000)
    initial_total = account_a.balance + account_b.balance

    def do_transfers():
        for _ in range(iterations):
            account_a.transfer_to(account_b, 100)
            account_b.transfer_to(account_a, 100)

    threads = []
    for _ in range(num_threads):
        t = threading.Thread(target=do_transfers)
        threads.append(t)
        t.start()

    for t in threads:
        t.join()

    final_total = account_a.balance + account_b.balance
    print(f"Bank Simulation ({num_threads} threads, {iterations} iterations)")
    print(f"  Initial total: {initial_total}")
    print(f"  Final total:   {final_total}")
    print(f"  Alice balance: {account_a.balance}")
    print(f"  Bob balance:   {account_b.balance}")
    print(f"  Transactions:  {len(account_a.transaction_log) + len(account_b.transaction_log)}")


def run_ticket_simulation(num_threads, tickets):
    pool = TicketPool(tickets)
    results = {"success": 0, "failed": 0}
    lock = threading.Lock()

    def book_tickets():
        for _ in range(tickets // num_threads):
            rid = pool.reserve("Customer", 1)
            with lock:
                if rid is not None:
                    results["success"] += 1
                else:
                    results["failed"] += 1

    threads = []
    for _ in range(num_threads):
        t = threading.Thread(target=book_tickets)
        threads.append(t)
        t.start()

    for t in threads:
        t.join()

    print(f"Ticket Simulation ({num_threads} threads, {tickets} tickets)")
    print(f"  Successful bookings: {results['success']}")
    print(f"  Failed bookings:     {results['failed']}")
    print(f"  Remaining tickets:   {pool.available}")


def run_inventory_simulation(num_threads, quantity):
    mgr = InventoryManager()
    mgr.add_product("Widget", quantity)

    def place_orders():
        for _ in range(quantity // num_threads):
            mgr.process_order("Widget", 1)

    def restock_items():
        for _ in range(quantity // (num_threads * 2)):
            mgr.restock("Widget", 1)

    threads = []
    for _ in range(num_threads):
        t = threading.Thread(target=place_orders)
        threads.append(t)
        t.start()
    for _ in range(num_threads // 2 or 1):
        t = threading.Thread(target=restock_items)
        threads.append(t)
        t.start()

    for t in threads:
        t.join()

    print(f"Inventory Simulation ({num_threads} threads)")
    print(f"  Initial stock:  {quantity}")
    print(f"  Final stock:    {mgr.products['Widget']}")
    print(f"  Orders placed:  {mgr.order_count}")


def run_config_simulation(num_threads):
    ConfigCache._instance = None
    ConfigCache._initialized = False
    instances = []
    lock = threading.Lock()

    def create_config():
        cfg = ConfigCache()
        cfg.set("db_host", f"host-{threading.current_thread().name}")
        with lock:
            instances.append(id(cfg))

    threads = []
    for _ in range(num_threads):
        t = threading.Thread(target=create_config)
        threads.append(t)
        t.start()

    for t in threads:
        t.join()

    unique = len(set(instances))
    print(f"Config Simulation ({num_threads} threads)")
    print(f"  Instances created: {len(instances)}")
    print(f"  Unique instances:  {unique}")
    cfg = ConfigCache()
    print(f"  Final db_host:     {cfg.get('db_host')}")


def run_file_counter_simulation(num_threads, filepath):
    def increment():
        for _ in range(10):
            file_based_counter(filepath)

    threads = []
    for _ in range(num_threads):
        t = threading.Thread(target=increment)
        threads.append(t)
        t.start()

    for t in threads:
        t.join()

    with open(filepath, "r") as f:
        final = int(f.read().strip())

    expected = num_threads * 10
    print(f"File Counter Simulation ({num_threads} threads)")
    print(f"  Expected count: {expected}")
    print(f"  Actual count:   {final}")

    try:
        os.remove(filepath)
    except OSError:
        pass


def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <command> [args...]")
        print("Commands:")
        print("  bank <threads> <iterations>     Bank transfer simulation")
        print("  tickets <threads> <total>        Ticket booking simulation")
        print("  inventory <threads> <quantity>   Inventory management simulation")
        print("  config <threads>                 Singleton config simulation")
        print("  filecounter <threads>            File-based counter simulation")
        sys.exit(0)

    cmd = sys.argv[1]

    if cmd == "bank":
        threads = int(sys.argv[2]) if len(sys.argv) > 2 else 4
        iters = int(sys.argv[3]) if len(sys.argv) > 3 else 100
        run_bank_simulation(threads, iters)

    elif cmd == "tickets":
        threads = int(sys.argv[2]) if len(sys.argv) > 2 else 4
        total = int(sys.argv[3]) if len(sys.argv) > 3 else 100
        run_ticket_simulation(threads, total)

    elif cmd == "inventory":
        threads = int(sys.argv[2]) if len(sys.argv) > 2 else 4
        qty = int(sys.argv[3]) if len(sys.argv) > 3 else 200
        run_inventory_simulation(threads, qty)

    elif cmd == "config":
        threads = int(sys.argv[2]) if len(sys.argv) > 2 else 8
        run_config_simulation(threads)

    elif cmd == "filecounter":
        threads = int(sys.argv[2]) if len(sys.argv) > 2 else 4
        run_file_counter_simulation(threads, "/tmp/race_counter.txt")

    else:
        print(f"Unknown command: {cmd}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
