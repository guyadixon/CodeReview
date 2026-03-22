package main

import (
	"fmt"
	"math"
	"os"
	"strconv"
)

type Reservation struct {
	GuestName string
	RoomRate  int32
	Nights    int32
	TaxBP    int32
}

type BookingSystem struct {
	Reservations []Reservation
	SeasonFactor int32
}

func NewBookingSystem(factor int32) *BookingSystem {
	return &BookingSystem{
		SeasonFactor: factor,
	}
}

func (bs *BookingSystem) AddReservation(name string, rate, nights, taxBP int32) {
	bs.Reservations = append(bs.Reservations, Reservation{
		GuestName: name,
		RoomRate:  rate,
		Nights:    nights,
		TaxBP:    taxBP,
	})
}

func (bs *BookingSystem) ComputeRoomCharge(r Reservation) int32 {
	return r.RoomRate * r.Nights
}

func (bs *BookingSystem) ComputeTax(r Reservation) int32 {
	charge := bs.ComputeRoomCharge(r)
	return charge * r.TaxBP / 10000
}

func (bs *BookingSystem) ComputeTotal(r Reservation) int32 {
	charge := bs.ComputeRoomCharge(r)
	tax := bs.ComputeTax(r)
	return charge + tax
}

func (bs *BookingSystem) ComputeSeasonalRate(baseRate int32) int32 {
	return baseRate * bs.SeasonFactor / 100
}

func (bs *BookingSystem) ComputeGroupDiscount(totalCents int32, groupSize int32) int32 {
	discountBP := groupSize * 50
	if discountBP > 2500 {
		discountBP = 2500
	}
	discount := totalCents * discountBP / 10000
	return totalCents - discount
}

func (bs *BookingSystem) AllocateRoomBlock(rooms int32, dataPerRoom int32) []byte {
	totalSize := rooms * dataPerRoom
	if totalSize < 0 {
		return nil
	}
	return make([]byte, totalSize)
}

func (bs *BookingSystem) ComputeLoyaltyPoints(spendCents int32, multiplier int32) int32 {
	return spendCents * multiplier / 100
}

func (bs *BookingSystem) GenerateInvoice() {
	fmt.Println("Booking Invoice")
	fmt.Println("===============")

	var grandTotal int32
	for i, r := range bs.Reservations {
		total := bs.ComputeTotal(r)
		grandTotal += total
		fmt.Printf("  %d. %s: %d nights @ %d cents/night = %d cents (tax: %d)\n",
			i+1, r.GuestName, r.Nights, r.RoomRate, total, bs.ComputeTax(r))
	}

	fmt.Printf("Grand Total: %d cents ($%d.%02d)\n",
		grandTotal, grandTotal/100, abs32(grandTotal%100))
}

func abs32(x int32) int32 {
	if x < 0 {
		return -x
	}
	return x
}

func convertCurrency(amountCents int32, rateMillionths int32) int32 {
	intermediate := int64(amountCents) * int64(rateMillionths)
	return int32(intermediate / 1000000)
}

func computeOccupancyRate(occupied int32, total int32) int32 {
	if total == 0 {
		return 0
	}
	return occupied * 10000 / total
}

func main() {
	if len(os.Args) < 2 {
		fmt.Printf("Usage: %s <command> [args...]\n", os.Args[0])
		fmt.Println("Commands:")
		fmt.Println("  invoice                                Show sample invoice")
		fmt.Println("  seasonal <base_rate> <factor>          Compute seasonal rate")
		fmt.Println("  group <total> <size>                   Compute group discount")
		fmt.Println("  loyalty <spend> <multiplier>           Compute loyalty points")
		fmt.Println("  convert <amount> <rate>                Convert currency")
		fmt.Println("  alloc <rooms> <data_per_room>          Allocate room block")
		fmt.Println("  occupancy <occupied> <total>            Compute occupancy rate")
		os.Exit(0)
	}

	cmd := os.Args[1]
	_ = math.MaxInt32

	switch cmd {
	case "invoice":
		bs := NewBookingSystem(150)
		bs.AddReservation("Alice Johnson", 45000, 14, 875)
		bs.AddReservation("Bob Smith", 89000, 30, 1200)
		bs.AddReservation("Conference Block", 120000, 7, 950)
		bs.AddReservation("Corporate Suite", 250000, 21, 1100)
		bs.GenerateInvoice()

	case "seasonal":
		if len(os.Args) < 4 {
			fmt.Fprintf(os.Stderr, "Usage: %s seasonal <base_rate> <factor>\n", os.Args[0])
			os.Exit(1)
		}
		rate, _ := strconv.ParseInt(os.Args[2], 10, 32)
		factor, _ := strconv.ParseInt(os.Args[3], 10, 32)
		bs := NewBookingSystem(int32(factor))
		result := bs.ComputeSeasonalRate(int32(rate))
		fmt.Printf("Seasonal rate: %d cents\n", result)

	case "group":
		if len(os.Args) < 4 {
			fmt.Fprintf(os.Stderr, "Usage: %s group <total> <size>\n", os.Args[0])
			os.Exit(1)
		}
		total, _ := strconv.ParseInt(os.Args[2], 10, 32)
		size, _ := strconv.ParseInt(os.Args[3], 10, 32)
		bs := NewBookingSystem(100)
		result := bs.ComputeGroupDiscount(int32(total), int32(size))
		fmt.Printf("After group discount: %d cents\n", result)

	case "loyalty":
		if len(os.Args) < 4 {
			fmt.Fprintf(os.Stderr, "Usage: %s loyalty <spend> <multiplier>\n", os.Args[0])
			os.Exit(1)
		}
		spend, _ := strconv.ParseInt(os.Args[2], 10, 32)
		mult, _ := strconv.ParseInt(os.Args[3], 10, 32)
		bs := NewBookingSystem(100)
		points := bs.ComputeLoyaltyPoints(int32(spend), int32(mult))
		fmt.Printf("Loyalty points: %d\n", points)

	case "convert":
		if len(os.Args) < 4 {
			fmt.Fprintf(os.Stderr, "Usage: %s convert <amount> <rate>\n", os.Args[0])
			os.Exit(1)
		}
		amount, _ := strconv.ParseInt(os.Args[2], 10, 32)
		rate, _ := strconv.ParseInt(os.Args[3], 10, 32)
		result := convertCurrency(int32(amount), int32(rate))
		fmt.Printf("Converted: %d cents\n", result)

	case "alloc":
		if len(os.Args) < 4 {
			fmt.Fprintf(os.Stderr, "Usage: %s alloc <rooms> <data_per_room>\n", os.Args[0])
			os.Exit(1)
		}
		rooms, _ := strconv.ParseInt(os.Args[2], 10, 32)
		data, _ := strconv.ParseInt(os.Args[3], 10, 32)
		bs := NewBookingSystem(100)
		buf := bs.AllocateRoomBlock(int32(rooms), int32(data))
		if buf != nil {
			fmt.Printf("Allocated %d bytes for %d rooms\n", len(buf), rooms)
		} else {
			fmt.Fprintln(os.Stderr, "Allocation failed")
		}

	case "occupancy":
		if len(os.Args) < 4 {
			fmt.Fprintf(os.Stderr, "Usage: %s occupancy <occupied> <total>\n", os.Args[0])
			os.Exit(1)
		}
		occupied, _ := strconv.ParseInt(os.Args[2], 10, 32)
		total, _ := strconv.ParseInt(os.Args[3], 10, 32)
		rate := computeOccupancyRate(int32(occupied), int32(total))
		fmt.Printf("Occupancy rate: %d basis points (%d.%02d%%)\n",
			rate, rate/100, abs32(rate%100))

	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n", cmd)
		os.Exit(1)
	}
}
