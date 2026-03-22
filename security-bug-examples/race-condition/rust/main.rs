use std::env;
use std::process;
use std::sync::Arc;
use std::thread;

struct UnsafeSendCell<T>(std::cell::UnsafeCell<T>);
unsafe impl<T> Send for UnsafeSendCell<T> {}
unsafe impl<T> Sync for UnsafeSendCell<T> {}

impl<T> UnsafeSendCell<T> {
    fn new(value: T) -> Self {
        UnsafeSendCell(std::cell::UnsafeCell::new(value))
    }
    fn get(&self) -> *mut T {
        self.0.get()
    }
}

struct BankAccount {
    owner: String,
    balance: i64,
}

impl BankAccount {
    fn new(owner: &str, balance: i64) -> Self {
        BankAccount {
            owner: owner.to_string(),
            balance,
        }
    }
}

fn run_bank_simulation(num_threads: usize, iterations: usize) {
    let account = Arc::new(UnsafeSendCell::new(BankAccount::new("Shared", 10000)));

    let mut handles = vec![];
    for _ in 0..num_threads {
        let acc = Arc::clone(&account);
        handles.push(thread::spawn(move || {
            for _ in 0..iterations {
                unsafe {
                    let a = &mut *acc.get();
                    let current = a.balance;
                    thread::yield_now();
                    a.balance = current + 100;
                }
                unsafe {
                    let a = &mut *acc.get();
                    let current = a.balance;
                    thread::yield_now();
                    a.balance = current - 100;
                }
            }
        }));
    }

    for h in handles {
        h.join().unwrap();
    }

    let final_balance = unsafe { (*account.get()).balance };
    println!("Bank Simulation ({} threads, {} iterations)", num_threads, iterations);
    println!("  Initial balance: 10000");
    println!("  Final balance:   {}", final_balance);
}

struct TicketPool {
    available: i32,
    sold: i32,
}

fn run_ticket_simulation(num_threads: usize, total_tickets: i32) {
    let pool = Arc::new(UnsafeSendCell::new(TicketPool {
        available: total_tickets,
        sold: 0,
    }));

    let mut handles = vec![];
    let per_thread = total_tickets / num_threads as i32;

    for _ in 0..num_threads {
        let p = Arc::clone(&pool);
        handles.push(thread::spawn(move || {
            for _ in 0..per_thread {
                unsafe {
                    let tp = &mut *p.get();
                    if tp.available > 0 {
                        thread::yield_now();
                        tp.available -= 1;
                        tp.sold += 1;
                    }
                }
            }
        }));
    }

    for h in handles {
        h.join().unwrap();
    }

    let (avail, sold) = unsafe {
        let tp = &*pool.get();
        (tp.available, tp.sold)
    };
    println!("Ticket Simulation ({} threads, {} tickets)", num_threads, total_tickets);
    println!("  Available: {}", avail);
    println!("  Sold:      {}", sold);
    println!("  Total:     {}", avail + sold);
}

struct SharedCounter {
    value: i64,
}

fn run_counter_simulation(num_threads: usize, increments: usize) {
    let counter = Arc::new(UnsafeSendCell::new(SharedCounter { value: 0 }));

    let mut handles = vec![];
    for _ in 0..num_threads {
        let c = Arc::clone(&counter);
        handles.push(thread::spawn(move || {
            for _ in 0..increments {
                unsafe {
                    let ctr = &mut *c.get();
                    let current = ctr.value;
                    thread::yield_now();
                    ctr.value = current + 1;
                }
            }
        }));
    }

    for h in handles {
        h.join().unwrap();
    }

    let final_val = unsafe { (*counter.get()).value };
    let expected = (num_threads * increments) as i64;
    println!("Counter Simulation ({} threads, {} increments each)", num_threads, increments);
    println!("  Expected: {}", expected);
    println!("  Actual:   {}", final_val);
}

static mut GLOBAL_CONFIG: Option<Vec<(String, String)>> = None;
static mut CONFIG_INITIALIZED: bool = false;

fn get_global_config() -> &'static mut Vec<(String, String)> {
    unsafe {
        if !CONFIG_INITIALIZED {
            thread::yield_now();
            GLOBAL_CONFIG = Some(Vec::new());
            CONFIG_INITIALIZED = true;
        }
        GLOBAL_CONFIG.as_mut().unwrap()
    }
}

fn run_singleton_simulation(num_threads: usize) {
    unsafe {
        GLOBAL_CONFIG = None;
        CONFIG_INITIALIZED = false;
    }

    let mut handles = vec![];
    for i in 0..num_threads {
        handles.push(thread::spawn(move || {
            let cfg = get_global_config();
            cfg.push((format!("worker-{}", i), "active".to_string()));
        }));
    }

    for h in handles {
        let _ = h.join();
    }

    let cfg = get_global_config();
    println!("Singleton Simulation ({} threads)", num_threads);
    println!("  Config entries: {}", cfg.len());
}

struct Inventory {
    stock: i32,
    orders: i32,
}

fn run_inventory_simulation(num_threads: usize, quantity: i32) {
    let inv = Arc::new(UnsafeSendCell::new(Inventory {
        stock: quantity,
        orders: 0,
    }));

    let mut handles = vec![];
    let per_thread = quantity / num_threads as i32;

    for _ in 0..num_threads {
        let inv_ref = Arc::clone(&inv);
        handles.push(thread::spawn(move || {
            for _ in 0..per_thread {
                unsafe {
                    let i = &mut *inv_ref.get();
                    if i.stock > 0 {
                        thread::yield_now();
                        i.stock -= 1;
                        i.orders += 1;
                    }
                }
            }
        }));
    }

    for h in handles {
        h.join().unwrap();
    }

    let (stock, orders) = unsafe {
        let i = &*inv.get();
        (i.stock, i.orders)
    };
    println!("Inventory Simulation ({} threads)", num_threads);
    println!("  Initial stock: {}", quantity);
    println!("  Final stock:   {}", stock);
    println!("  Orders:        {}", orders);
}

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        println!("Usage: {} <command> [args...]", args[0]);
        println!("Commands:");
        println!("  bank <threads> <iterations>     Bank balance simulation");
        println!("  tickets <threads> <total>        Ticket booking simulation");
        println!("  counter <threads> <increments>   Shared counter simulation");
        println!("  singleton <threads>              Global config simulation");
        println!("  inventory <threads> <quantity>   Inventory simulation");
        process::exit(0);
    }

    let cmd = &args[1];

    match cmd.as_str() {
        "bank" => {
            let t = parse_arg(&args, 2, 4);
            let i = parse_arg(&args, 3, 100);
            run_bank_simulation(t, i);
        }
        "tickets" => {
            let t = parse_arg(&args, 2, 4);
            let n = parse_arg(&args, 3, 100);
            run_ticket_simulation(t, n as i32);
        }
        "counter" => {
            let t = parse_arg(&args, 2, 4);
            let i = parse_arg(&args, 3, 1000);
            run_counter_simulation(t, i);
        }
        "singleton" => {
            let t = parse_arg(&args, 2, 8);
            run_singleton_simulation(t);
        }
        "inventory" => {
            let t = parse_arg(&args, 2, 4);
            let q = parse_arg(&args, 3, 200);
            run_inventory_simulation(t, q as i32);
        }
        _ => {
            eprintln!("Unknown command: {}", cmd);
            process::exit(1);
        }
    }
}

fn parse_arg(args: &[String], index: usize, default: usize) -> usize {
    if index < args.len() {
        args[index].parse().unwrap_or(default)
    } else {
        default
    }
}
