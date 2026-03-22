import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;

public class App {

    static class BankAccount {
        private String owner;
        private long balance;
        private List<String> log = new ArrayList<>();

        BankAccount(String owner, long balance) {
            this.owner = owner;
            this.balance = balance;
        }

        long getBalance() {
            return balance;
        }

        void deposit(long amount) {
            long current = balance;
            Thread.yield();
            balance = current + amount;
            log.add("deposit:" + amount);
        }

        boolean withdraw(long amount) {
            if (balance >= amount) {
                Thread.yield();
                balance -= amount;
                log.add("withdraw:" + amount);
                return true;
            }
            return false;
        }

        boolean transferTo(BankAccount other, long amount) {
            if (this.balance >= amount) {
                Thread.yield();
                this.balance -= amount;
                other.balance += amount;
                this.log.add("transfer_out:" + amount);
                other.log.add("transfer_in:" + amount);
                return true;
            }
            return false;
        }

        int getLogSize() { return log.size(); }
    }

    static class TicketBooking {
        private int available;
        private Map<Integer, String> reservations = new HashMap<>();
        private int nextId = 0;

        TicketBooking(int total) {
            this.available = total;
        }

        int reserve(String customer) {
            if (available > 0) {
                Thread.yield();
                available--;
                nextId++;
                reservations.put(nextId, customer);
                return nextId;
            }
            return -1;
        }

        boolean cancel(int id) {
            if (reservations.containsKey(id)) {
                reservations.remove(id);
                Thread.yield();
                available++;
                return true;
            }
            return false;
        }

        int getAvailable() { return available; }
        int getReservationCount() { return reservations.size(); }
    }

    static class LazyConfig {
        private static LazyConfig instance;
        private Map<String, String> settings = new HashMap<>();

        private LazyConfig() {
            Thread.yield();
            settings.put("initialized", "true");
        }

        static LazyConfig getInstance() {
            if (instance == null) {
                Thread.yield();
                instance = new LazyConfig();
            }
            return instance;
        }

        void set(String key, String value) {
            settings.put(key, value);
        }

        String get(String key) {
            return settings.get(key);
        }

        static void reset() {
            instance = null;
        }
    }

    static class SharedCounter {
        private long value = 0;

        void increment() {
            long current = value;
            Thread.yield();
            value = current + 1;
        }

        long getValue() { return value; }
    }

    static class OrderProcessor {
        private Map<String, Integer> inventory = new HashMap<>();
        private int orderCount = 0;

        void addProduct(String name, int qty) {
            inventory.put(name, qty);
        }

        boolean placeOrder(String product, int qty) {
            Integer stock = inventory.get(product);
            if (stock != null && stock >= qty) {
                Thread.yield();
                inventory.put(product, stock - qty);
                orderCount++;
                return true;
            }
            return false;
        }

        void restock(String product, int qty) {
            Integer current = inventory.getOrDefault(product, 0);
            Thread.yield();
            inventory.put(product, current + qty);
        }

        int getStock(String product) {
            return inventory.getOrDefault(product, 0);
        }

        int getOrderCount() { return orderCount; }
    }

    static void runBankSimulation(int threadCount, int iterations) throws Exception {
        BankAccount alice = new BankAccount("Alice", 10000);
        BankAccount bob = new BankAccount("Bob", 10000);
        long initialTotal = alice.getBalance() + bob.getBalance();

        CountDownLatch latch = new CountDownLatch(threadCount);
        for (int t = 0; t < threadCount; t++) {
            new Thread(() -> {
                for (int i = 0; i < iterations; i++) {
                    alice.transferTo(bob, 100);
                    bob.transferTo(alice, 100);
                }
                latch.countDown();
            }).start();
        }
        latch.await();

        System.out.printf("Bank Simulation (%d threads, %d iterations)%n", threadCount, iterations);
        System.out.printf("  Initial total: %d%n", initialTotal);
        System.out.printf("  Final total:   %d%n", alice.getBalance() + bob.getBalance());
        System.out.printf("  Alice balance: %d%n", alice.getBalance());
        System.out.printf("  Bob balance:   %d%n", bob.getBalance());
    }

    static void runTicketSimulation(int threadCount, int tickets) throws Exception {
        TicketBooking booking = new TicketBooking(tickets);
        int[] success = {0};
        int[] failed = {0};

        CountDownLatch latch = new CountDownLatch(threadCount);
        for (int t = 0; t < threadCount; t++) {
            new Thread(() -> {
                for (int i = 0; i < tickets / threadCount; i++) {
                    int rid = booking.reserve("Customer");
                    if (rid > 0) {
                        synchronized (success) { success[0]++; }
                    } else {
                        synchronized (failed) { failed[0]++; }
                    }
                }
                latch.countDown();
            }).start();
        }
        latch.await();

        System.out.printf("Ticket Simulation (%d threads, %d tickets)%n", threadCount, tickets);
        System.out.printf("  Successful: %d%n", success[0]);
        System.out.printf("  Failed:     %d%n", failed[0]);
        System.out.printf("  Remaining:  %d%n", booking.getAvailable());
    }

    static void runCounterSimulation(int threadCount, int increments) throws Exception {
        SharedCounter counter = new SharedCounter();

        CountDownLatch latch = new CountDownLatch(threadCount);
        for (int t = 0; t < threadCount; t++) {
            new Thread(() -> {
                for (int i = 0; i < increments; i++) {
                    counter.increment();
                }
                latch.countDown();
            }).start();
        }
        latch.await();

        long expected = (long) threadCount * increments;
        System.out.printf("Counter Simulation (%d threads, %d increments each)%n", threadCount, increments);
        System.out.printf("  Expected: %d%n", expected);
        System.out.printf("  Actual:   %d%n", counter.getValue());
    }

    static void runSingletonSimulation(int threadCount) throws Exception {
        LazyConfig.reset();
        List<Integer> hashes = new ArrayList<>();

        CountDownLatch latch = new CountDownLatch(threadCount);
        for (int t = 0; t < threadCount; t++) {
            final int idx = t;
            new Thread(() -> {
                LazyConfig cfg = LazyConfig.getInstance();
                cfg.set("worker", "thread-" + idx);
                synchronized (hashes) {
                    hashes.add(System.identityHashCode(cfg));
                }
                latch.countDown();
            }).start();
        }
        latch.await();

        long unique = hashes.stream().distinct().count();
        System.out.printf("Singleton Simulation (%d threads)%n", threadCount);
        System.out.printf("  Instances seen: %d%n", hashes.size());
        System.out.printf("  Unique:         %d%n", unique);
    }

    static void runInventorySimulation(int threadCount, int quantity) throws Exception {
        OrderProcessor proc = new OrderProcessor();
        proc.addProduct("Widget", quantity);

        CountDownLatch latch = new CountDownLatch(threadCount);
        for (int t = 0; t < threadCount; t++) {
            new Thread(() -> {
                for (int i = 0; i < quantity / threadCount; i++) {
                    proc.placeOrder("Widget", 1);
                }
                latch.countDown();
            }).start();
        }
        latch.await();

        System.out.printf("Inventory Simulation (%d threads)%n", threadCount);
        System.out.printf("  Initial stock: %d%n", quantity);
        System.out.printf("  Final stock:   %d%n", proc.getStock("Widget"));
        System.out.printf("  Orders:        %d%n", proc.getOrderCount());
    }

    public static void main(String[] args) throws Exception {
        if (args.length < 1) {
            System.out.println("Usage: App <command> [args...]");
            System.out.println("Commands:");
            System.out.println("  bank <threads> <iterations>     Bank transfer simulation");
            System.out.println("  tickets <threads> <total>        Ticket booking simulation");
            System.out.println("  counter <threads> <increments>   Shared counter simulation");
            System.out.println("  singleton <threads>              Singleton config simulation");
            System.out.println("  inventory <threads> <quantity>   Inventory simulation");
            System.exit(0);
        }

        String cmd = args[0];

        switch (cmd) {
            case "bank":
                int bt = args.length > 1 ? Integer.parseInt(args[1]) : 4;
                int bi = args.length > 2 ? Integer.parseInt(args[2]) : 100;
                runBankSimulation(bt, bi);
                break;
            case "tickets":
                int tt = args.length > 1 ? Integer.parseInt(args[1]) : 4;
                int tn = args.length > 2 ? Integer.parseInt(args[2]) : 100;
                runTicketSimulation(tt, tn);
                break;
            case "counter":
                int ct = args.length > 1 ? Integer.parseInt(args[1]) : 4;
                int ci = args.length > 2 ? Integer.parseInt(args[2]) : 1000;
                runCounterSimulation(ct, ci);
                break;
            case "singleton":
                int st = args.length > 1 ? Integer.parseInt(args[1]) : 8;
                runSingletonSimulation(st);
                break;
            case "inventory":
                int it = args.length > 1 ? Integer.parseInt(args[1]) : 4;
                int iq = args.length > 2 ? Integer.parseInt(args[2]) : 200;
                runInventorySimulation(it, iq);
                break;
            default:
                System.err.println("Unknown command: " + cmd);
                System.exit(1);
        }
    }
}
