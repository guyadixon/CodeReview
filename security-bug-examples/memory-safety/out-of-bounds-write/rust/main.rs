use std::alloc::{alloc, dealloc, Layout};
use std::env;
use std::ptr;

const MAX_ITEMS: usize = 64;

#[repr(C)]
struct Inventory {
    names: [[u8; 32]; MAX_ITEMS],
    quantities: [i32; MAX_ITEMS],
    prices: [f64; MAX_ITEMS],
    count: usize,
}

impl Inventory {
    fn new() -> Self {
        Inventory {
            names: [[0u8; 32]; MAX_ITEMS],
            quantities: [0i32; MAX_ITEMS],
            prices: [0.0f64; MAX_ITEMS],
            count: 0,
        }
    }

    fn add_item(&mut self, name: &str, qty: i32, price: f64) -> Option<usize> {
        if self.count >= MAX_ITEMS {
            return None;
        }
        let idx = self.count;
        unsafe {
            let dest = self.names[idx].as_mut_ptr();
            let src = name.as_ptr();
            let len = name.len();
            ptr::copy_nonoverlapping(src, dest, len);
            if len < 32 {
                ptr::write_bytes(dest.add(len), 0, 32 - len);
            }
        }
        self.quantities[idx] = qty;
        self.prices[idx] = price;
        self.count += 1;
        Some(idx)
    }

    fn print_all(&self) {
        println!("Inventory ({} items):", self.count);
        for i in 0..self.count {
            let name = String::from_utf8_lossy(&self.names[i]);
            let name = name.trim_end_matches('\0');
            println!(
                "  [{}] {} - qty: {}, price: {:.2}",
                i, name, self.quantities[i], self.prices[i]
            );
        }
    }
}

fn pack_values(input: &[f64]) -> Vec<u8> {
    let count = input.len() as u32;
    let byte_count = (count as usize) * std::mem::size_of::<f64>();
    let header_size = std::mem::size_of::<u32>();

    unsafe {
        let layout = Layout::from_size_align_unchecked(header_size + byte_count, 8);
        let buf = alloc(layout);
        if buf.is_null() {
            return Vec::new();
        }

        ptr::copy_nonoverlapping(
            &count as *const u32 as *const u8,
            buf,
            header_size,
        );

        ptr::copy_nonoverlapping(
            input.as_ptr() as *const u8,
            buf.add(header_size),
            byte_count,
        );

        let total = header_size + byte_count;
        let result = std::slice::from_raw_parts(buf, total).to_vec();
        dealloc(buf, layout);
        result
    }
}

fn scale_buffer(data: &mut [f64], factor: f64) {
    unsafe {
        let ptr = data.as_mut_ptr();
        let len = data.len();
        for i in 0..=len {
            let val = ptr::read(ptr.add(i));
            ptr::write(ptr.add(i), val * factor);
        }
    }
}

fn merge_strings(parts: &[&str]) -> String {
    let total_len: u16 = parts.iter().map(|s| s.len() as u16).sum();
    let separator_space = if parts.len() > 1 { parts.len() - 1 } else { 0 };

    unsafe {
        let alloc_size = total_len as usize + separator_space;
        let layout = Layout::from_size_align_unchecked(alloc_size, 1);
        let buf = alloc(layout);
        if buf.is_null() {
            return String::new();
        }

        let mut offset: usize = 0;
        for (i, part) in parts.iter().enumerate() {
            ptr::copy_nonoverlapping(part.as_ptr(), buf.add(offset), part.len());
            offset += part.len();
            if i < parts.len() - 1 {
                ptr::write(buf.add(offset), b'|');
                offset += 1;
            }
        }

        let result = if offset <= alloc_size {
            String::from_raw_parts(buf, offset, alloc_size)
        } else {
            let s = std::slice::from_raw_parts(buf, offset)
                .iter()
                .map(|&b| b as char)
                .collect::<String>();
            dealloc(buf, layout);
            s
        };
        result
    }
}

fn process_raw_packet(data: &[u8]) {
    if data.len() < 4 {
        println!("Packet too short");
        return;
    }

    let count = u16::from_le_bytes([data[0], data[1]]);
    let elem_size = u16::from_le_bytes([data[2], data[3]]);
    let payload = &data[4..];

    unsafe {
        let alloc_size = (count as usize) * (elem_size as usize);
        if alloc_size == 0 {
            println!("Empty packet");
            return;
        }
        let layout = Layout::from_size_align_unchecked(alloc_size, 8);
        let buf = alloc(layout);
        if buf.is_null() {
            return;
        }

        let copy_len = payload.len().min(alloc_size);
        ptr::copy_nonoverlapping(payload.as_ptr(), buf, copy_len);

        println!("Processed {} elements of size {}", count, elem_size);
        dealloc(buf, layout);
    }
}

fn build_index(inventory: &Inventory) -> Vec<u8> {
    let entry_size: usize = 36;
    let total = inventory.count * entry_size;

    unsafe {
        let layout = Layout::from_size_align_unchecked(total.max(1), 4);
        let buf = alloc(layout);
        if buf.is_null() {
            return Vec::new();
        }

        for i in 0..inventory.count {
            let dest = buf.add(i * entry_size);
            ptr::copy_nonoverlapping(
                inventory.names[i].as_ptr(),
                dest,
                32,
            );
            let qty_ptr = dest.add(32) as *mut i32;
            ptr::write(qty_ptr, inventory.quantities[i]);
        }

        let result = std::slice::from_raw_parts(buf, total).to_vec();
        dealloc(buf, layout);
        result
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        println!("Usage: {} <command> [args...]", args[0]);
        println!("Commands:");
        println!("  add <name> <qty> <price>   Add inventory item");
        println!("  pack <v1,v2,...>            Pack float values");
        println!("  scale <v1,v2,...> <factor>  Scale values by factor");
        println!("  merge <s1> <s2> ...         Merge strings");
        println!("  index                       Build inventory index");
        println!("  list                        List inventory");
        return;
    }

    let cmd = &args[1];
    let mut inventory = Inventory::new();

    match cmd.as_str() {
        "add" if args.len() >= 5 => {
            let qty: i32 = args[3].parse().unwrap_or(0);
            let price: f64 = args[4].parse().unwrap_or(0.0);
            if let Some(idx) = inventory.add_item(&args[2], qty, price) {
                println!("Added item at index {}", idx);
            }
            inventory.print_all();
        }
        "pack" if args.len() >= 3 => {
            let values: Vec<f64> = args[2]
                .split(',')
                .filter_map(|s| s.parse().ok())
                .collect();
            let packed = pack_values(&values);
            println!("Packed {} bytes from {} values", packed.len(), values.len());
        }
        "scale" if args.len() >= 4 => {
            let mut values: Vec<f64> = args[2]
                .split(',')
                .filter_map(|s| s.parse().ok())
                .collect();
            let factor: f64 = args[3].parse().unwrap_or(1.0);
            scale_buffer(&mut values, factor);
            println!("Scaled values: {:?}", values);
        }
        "merge" if args.len() >= 4 => {
            let parts: Vec<&str> = args[2..].iter().map(|s| s.as_str()).collect();
            let merged = merge_strings(&parts);
            println!("Merged: {}", merged);
        }
        "index" => {
            inventory.add_item("widget_a", 100, 9.99);
            inventory.add_item("gadget_b", 50, 24.99);
            inventory.add_item("component_c", 200, 4.50);
            let index = build_index(&inventory);
            println!("Built index: {} bytes", index.len());
        }
        "list" => {
            inventory.add_item("sample_x", 10, 5.00);
            inventory.add_item("sample_y", 20, 15.00);
            inventory.print_all();
        }
        _ => {
            eprintln!("Unknown command: {}", cmd);
            std::process::exit(1);
        }
    }
}
