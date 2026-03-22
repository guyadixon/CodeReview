package main

import (
	"fmt"
	"os"
	"strconv"
	"sync"
	"time"
)

type BankAccount struct {
	Owner   string
	Balance int64
	Log     []string
}

func (a *BankAccount) Deposit(amount int64) {
	current := a.Balance
	time.Sleep(time.Microsecond)
	a.Balance = current + amount
	a.Log = append(a.Log, fmt.Sprintf("deposit:%d", amount))
}

func (a *BankAccount) Withdraw(amount int64) bool {
	if a.Balance >= amount {
		time.Sleep(time.Microsecond)
		a.Balance -= amount
		a.Log = append(a.Log, fmt.Sprintf("withdraw:%d", amount))
		return true
	}
	return false
}

func (a *BankAccount) TransferTo(other *BankAccount, amount int64) bool {
	if a.Balance >= amount {
		time.Sleep(time.Microsecond)
		a.Balance -= amount
		other.Balance += amount
		a.Log = append(a.Log, fmt.Sprintf("transfer_out:%d", amount))
		other.Log = append(other.Log, fmt.Sprintf("transfer_in:%d", amount))
		return true
	}
	return false
}

type TicketPool struct {
	Available    int
	Reservations map[int]string
	NextID       int
}

func NewTicketPool(total int) *TicketPool {
	return &TicketPool{
		Available:    total,
		Reservations: make(map[int]string),
	}
}

func (tp *TicketPool) Reserve(customer string) int {
	if tp.Available > 0 {
		time.Sleep(time.Microsecond)
		tp.Available--
		tp.NextID++
		tp.Reservations[tp.NextID] = customer
		return tp.NextID
	}
	return -1
}

func (tp *TicketPool) Cancel(id int) bool {
	if _, ok := tp.Reservations[id]; ok {
		delete(tp.Reservations, id)
		time.Sleep(time.Microsecond)
		tp.Available++
		return true
	}
	return false
}

type Inventory struct {
	Products   map[string]int
	OrderCount int
}

func NewInventory() *Inventory {
	return &Inventory{Products: make(map[string]int)}
}

func (inv *Inventory) AddProduct(name string, qty int) {
	inv.Products[name] = qty
}

func (inv *Inventory) PlaceOrder(name string, qty int) bool {
	stock, ok := inv.Products[name]
	if ok && stock >= qty {
		time.Sleep(time.Microsecond)
		inv.Products[name] = stock - qty
		inv.OrderCount++
		return true
	}
	return false
}

func (inv *Inventory) Restock(name string, qty int) {
	current := inv.Products[name]
	time.Sleep(time.Microsecond)
	inv.Products[name] = current + qty
}

var (
	configInstance *ConfigSingleton
)

type ConfigSingleton struct {
	Settings map[string]string
}

func GetConfig() *ConfigSingleton {
	if configInstance == nil {
		time.Sleep(time.Microsecond)
		configInstance = &ConfigSingleton{
			Settings: make(map[string]string),
		}
	}
	return configInstance
}

func runBankSimulation(threads, iterations int) {
	alice := &BankAccount{Owner: "Alice", Balance: 10000}
	bob := &BankAccount{Owner: "Bob", Balance: 10000}
	initialTotal := alice.Balance + bob.Balance

	var wg sync.WaitGroup
	for t := 0; t < threads; t++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				alice.TransferTo(bob, 100)
				bob.TransferTo(alice, 100)
			}
		}()
	}
	wg.Wait()

	finalTotal := alice.Balance + bob.Balance
	fmt.Printf("Bank Simulation (%d goroutines, %d iterations)\n", threads, iterations)
	fmt.Printf("  Initial total: %d\n", initialTotal)
	fmt.Printf("  Final total:   %d\n", finalTotal)
	fmt.Printf("  Alice balance: %d\n", alice.Balance)
	fmt.Printf("  Bob balance:   %d\n", bob.Balance)
}

func runTicketSimulation(threads, tickets int) {
	pool := NewTicketPool(tickets)
	var successCount, failCount int
	var mu sync.Mutex

	var wg sync.WaitGroup
	perThread := tickets / threads
	for t := 0; t < threads; t++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < perThread; i++ {
				rid := pool.Reserve("Customer")
				mu.Lock()
				if rid > 0 {
					successCount++
				} else {
					failCount++
				}
				mu.Unlock()
			}
		}()
	}
	wg.Wait()

	fmt.Printf("Ticket Simulation (%d goroutines, %d tickets)\n", threads, tickets)
	fmt.Printf("  Successful: %d\n", successCount)
	fmt.Printf("  Failed:     %d\n", failCount)
	fmt.Printf("  Remaining:  %d\n", pool.Available)
}

func runInventorySimulation(threads, quantity int) {
	inv := NewInventory()
	inv.AddProduct("Widget", quantity)

	var wg sync.WaitGroup
	perThread := quantity / threads
	for t := 0; t < threads; t++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < perThread; i++ {
				inv.PlaceOrder("Widget", 1)
			}
		}()
	}
	wg.Wait()

	fmt.Printf("Inventory Simulation (%d goroutines)\n", threads)
	fmt.Printf("  Initial stock: %d\n", quantity)
	fmt.Printf("  Final stock:   %d\n", inv.Products["Widget"])
	fmt.Printf("  Orders:        %d\n", inv.OrderCount)
}

func runSingletonSimulation(threads int) {
	configInstance = nil
	var hashes []uintptr
	var mu sync.Mutex

	var wg sync.WaitGroup
	for t := 0; t < threads; t++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			cfg := GetConfig()
			cfg.Settings[fmt.Sprintf("worker-%d", id)] = "active"
			mu.Lock()
			hashes = append(hashes, uintptr(0))
			mu.Unlock()
		}(t)
	}
	wg.Wait()

	fmt.Printf("Singleton Simulation (%d goroutines)\n", threads)
	fmt.Printf("  Instances seen: %d\n", len(hashes))
	cfg := GetConfig()
	fmt.Printf("  Settings count: %d\n", len(cfg.Settings))
}

func runCounterSimulation(threads, increments int) {
	var counter int64

	var wg sync.WaitGroup
	for t := 0; t < threads; t++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < increments; i++ {
				current := counter
				time.Sleep(time.Microsecond)
				counter = current + 1
			}
		}()
	}
	wg.Wait()

	expected := int64(threads) * int64(increments)
	fmt.Printf("Counter Simulation (%d goroutines, %d increments each)\n", threads, increments)
	fmt.Printf("  Expected: %d\n", expected)
	fmt.Printf("  Actual:   %d\n", counter)
}

func main() {
	if len(os.Args) < 2 {
		fmt.Printf("Usage: %s <command> [args...]\n", os.Args[0])
		fmt.Println("Commands:")
		fmt.Println("  bank <goroutines> <iterations>     Bank transfer simulation")
		fmt.Println("  tickets <goroutines> <total>        Ticket booking simulation")
		fmt.Println("  inventory <goroutines> <quantity>   Inventory simulation")
		fmt.Println("  singleton <goroutines>              Singleton config simulation")
		fmt.Println("  counter <goroutines> <increments>   Shared counter simulation")
		os.Exit(0)
	}

	cmd := os.Args[1]

	switch cmd {
	case "bank":
		t := parseIntArg(2, 4)
		i := parseIntArg(3, 100)
		runBankSimulation(t, i)
	case "tickets":
		t := parseIntArg(2, 4)
		n := parseIntArg(3, 100)
		runTicketSimulation(t, n)
	case "inventory":
		t := parseIntArg(2, 4)
		q := parseIntArg(3, 200)
		runInventorySimulation(t, q)
	case "singleton":
		t := parseIntArg(2, 8)
		runSingletonSimulation(t)
	case "counter":
		t := parseIntArg(2, 4)
		i := parseIntArg(3, 100)
		runCounterSimulation(t, i)
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n", cmd)
		os.Exit(1)
	}
}

func parseIntArg(index, defaultVal int) int {
	if index < len(os.Args) {
		v, err := strconv.Atoi(os.Args[index])
		if err == nil {
			return v
		}
	}
	return defaultVal
}
