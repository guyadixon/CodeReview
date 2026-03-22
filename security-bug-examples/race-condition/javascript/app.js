const { Worker, isMainThread, parentPort, workerData } = require("worker_threads");
const fs = require("fs");
const path = require("path");

class BankAccount {
  constructor(owner, balance) {
    this.owner = owner;
    this.balance = balance;
    this.log = [];
  }

  async deposit(amount) {
    const current = this.balance;
    await new Promise((r) => setImmediate(r));
    this.balance = current + amount;
    this.log.push({ type: "deposit", amount });
  }

  async withdraw(amount) {
    if (this.balance >= amount) {
      await new Promise((r) => setImmediate(r));
      this.balance -= amount;
      this.log.push({ type: "withdrawal", amount });
      return true;
    }
    return false;
  }

  async transferTo(other, amount) {
    if (this.balance >= amount) {
      await new Promise((r) => setImmediate(r));
      this.balance -= amount;
      other.balance += amount;
      this.log.push({ type: "transfer_out", amount });
      other.log.push({ type: "transfer_in", amount });
      return true;
    }
    return false;
  }
}

class TicketPool {
  constructor(total) {
    this.available = total;
    this.reservations = {};
    this.nextId = 0;
  }

  async reserve(customer) {
    if (this.available > 0) {
      await new Promise((r) => setImmediate(r));
      this.available--;
      this.nextId++;
      this.reservations[this.nextId] = customer;
      return this.nextId;
    }
    return null;
  }

  async cancel(id) {
    if (this.reservations[id]) {
      delete this.reservations[id];
      await new Promise((r) => setImmediate(r));
      this.available++;
      return true;
    }
    return false;
  }
}

class Inventory {
  constructor() {
    this.products = {};
    this.orderCount = 0;
  }

  addProduct(name, qty) {
    this.products[name] = qty;
  }

  async placeOrder(name, qty) {
    if (this.products[name] !== undefined && this.products[name] >= qty) {
      const stock = this.products[name];
      await new Promise((r) => setImmediate(r));
      this.products[name] = stock - qty;
      this.orderCount++;
      return true;
    }
    return false;
  }

  async restock(name, qty) {
    const current = this.products[name] || 0;
    await new Promise((r) => setImmediate(r));
    this.products[name] = current + qty;
  }
}

let configInstance = null;

async function getConfig() {
  if (configInstance === null) {
    await new Promise((r) => setImmediate(r));
    configInstance = { settings: {} };
  }
  return configInstance;
}

function fileBasedCounter(filepath) {
  let count = 0;
  if (fs.existsSync(filepath)) {
    count = parseInt(fs.readFileSync(filepath, "utf8").trim(), 10);
  }
  count++;
  fs.writeFileSync(filepath, String(count));
  return count;
}

async function runBankSimulation(concurrency, iterations) {
  const alice = new BankAccount("Alice", 10000);
  const bob = new BankAccount("Bob", 10000);
  const initialTotal = alice.balance + bob.balance;

  const tasks = [];
  for (let t = 0; t < concurrency; t++) {
    tasks.push(
      (async () => {
        for (let i = 0; i < iterations; i++) {
          await alice.transferTo(bob, 100);
          await bob.transferTo(alice, 100);
        }
      })()
    );
  }
  await Promise.all(tasks);

  console.log(`Bank Simulation (${concurrency} tasks, ${iterations} iterations)`);
  console.log(`  Initial total: ${initialTotal}`);
  console.log(`  Final total:   ${alice.balance + bob.balance}`);
  console.log(`  Alice balance: ${alice.balance}`);
  console.log(`  Bob balance:   ${bob.balance}`);
}

async function runTicketSimulation(concurrency, totalTickets) {
  const pool = new TicketPool(totalTickets);
  let success = 0;
  let failed = 0;
  const perTask = Math.floor(totalTickets / concurrency);

  const tasks = [];
  for (let t = 0; t < concurrency; t++) {
    tasks.push(
      (async () => {
        for (let i = 0; i < perTask; i++) {
          const rid = await pool.reserve("Customer");
          if (rid !== null) success++;
          else failed++;
        }
      })()
    );
  }
  await Promise.all(tasks);

  console.log(`Ticket Simulation (${concurrency} tasks, ${totalTickets} tickets)`);
  console.log(`  Successful: ${success}`);
  console.log(`  Failed:     ${failed}`);
  console.log(`  Remaining:  ${pool.available}`);
}

async function runInventorySimulation(concurrency, quantity) {
  const inv = new Inventory();
  inv.addProduct("Widget", quantity);
  const perTask = Math.floor(quantity / concurrency);

  const tasks = [];
  for (let t = 0; t < concurrency; t++) {
    tasks.push(
      (async () => {
        for (let i = 0; i < perTask; i++) {
          await inv.placeOrder("Widget", 1);
        }
      })()
    );
  }
  tasks.push(
    (async () => {
      for (let i = 0; i < Math.floor(perTask / 2); i++) {
        await inv.restock("Widget", 1);
      }
    })()
  );
  await Promise.all(tasks);

  console.log(`Inventory Simulation (${concurrency} tasks)`);
  console.log(`  Initial stock: ${quantity}`);
  console.log(`  Final stock:   ${inv.products["Widget"]}`);
  console.log(`  Orders:        ${inv.orderCount}`);
}

async function runSingletonSimulation(concurrency) {
  configInstance = null;
  const instances = [];

  const tasks = [];
  for (let t = 0; t < concurrency; t++) {
    tasks.push(
      (async () => {
        const cfg = await getConfig();
        cfg.settings[`worker-${t}`] = "active";
        instances.push(cfg);
      })()
    );
  }
  await Promise.all(tasks);

  const unique = new Set(instances).size;
  console.log(`Singleton Simulation (${concurrency} tasks)`);
  console.log(`  Instances seen: ${instances.length}`);
  console.log(`  Unique:         ${unique}`);
}

async function runFileCounterSimulation(concurrency) {
  const filepath = path.join("/tmp", "race_counter_js.txt");
  try {
    fs.unlinkSync(filepath);
  } catch (_) {}

  const tasks = [];
  for (let t = 0; t < concurrency; t++) {
    tasks.push(
      (async () => {
        for (let i = 0; i < 10; i++) {
          fileBasedCounter(filepath);
          await new Promise((r) => setImmediate(r));
        }
      })()
    );
  }
  await Promise.all(tasks);

  const final_val = parseInt(fs.readFileSync(filepath, "utf8").trim(), 10);
  const expected = concurrency * 10;
  console.log(`File Counter Simulation (${concurrency} tasks)`);
  console.log(`  Expected: ${expected}`);
  console.log(`  Actual:   ${final_val}`);

  try {
    fs.unlinkSync(filepath);
  } catch (_) {}
}

async function main() {
  const args = process.argv.slice(2);

  if (args.length < 1) {
    console.log(`Usage: node app.js <command> [args...]`);
    console.log("Commands:");
    console.log("  bank <concurrency> <iterations>     Bank transfer simulation");
    console.log("  tickets <concurrency> <total>        Ticket booking simulation");
    console.log("  inventory <concurrency> <quantity>   Inventory simulation");
    console.log("  singleton <concurrency>              Config singleton simulation");
    console.log("  filecounter <concurrency>            File-based counter simulation");
    process.exit(0);
  }

  const cmd = args[0];
  const arg1 = parseInt(args[1], 10) || 4;
  const arg2 = parseInt(args[2], 10) || 100;

  switch (cmd) {
    case "bank":
      await runBankSimulation(arg1, arg2);
      break;
    case "tickets":
      await runTicketSimulation(arg1, arg2);
      break;
    case "inventory":
      await runInventorySimulation(arg1, arg2);
      break;
    case "singleton":
      await runSingletonSimulation(arg1);
      break;
    case "filecounter":
      await runFileCounterSimulation(arg1);
      break;
    default:
      console.error(`Unknown command: ${cmd}`);
      process.exit(1);
  }
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
