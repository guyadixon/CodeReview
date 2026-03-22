use std::env;
use std::process;

struct Measurement {
    sensor_id: u32,
    value: i32,
    timestamp: u32,
}

struct SensorArray {
    measurements: Vec<Measurement>,
    calibration_offset: i32,
}

impl SensorArray {
    fn new(offset: i32) -> Self {
        SensorArray {
            measurements: Vec::new(),
            calibration_offset: offset,
        }
    }

    fn add_reading(&mut self, sensor_id: u32, value: i32, timestamp: u32) {
        self.measurements.push(Measurement {
            sensor_id,
            value,
            timestamp,
        });
    }

    fn compute_average(&self) -> i32 {
        if self.measurements.is_empty() {
            return 0;
        }
        let mut sum: i32 = 0;
        for m in &self.measurements {
            sum = sum.wrapping_add(m.value);
        }
        sum / self.measurements.len() as i32
    }

    fn calibrated_value(&self, index: usize) -> i32 {
        let raw = self.measurements[index].value;
        raw.wrapping_add(self.calibration_offset)
    }

    fn compute_power_consumption(&self, voltage: i32, current: i32) -> i32 {
        voltage.wrapping_mul(current)
    }

    fn allocate_sample_buffer(&self, sample_count: u32, sample_size: u32) -> Vec<u8> {
        let total = sample_count.wrapping_mul(sample_size);
        vec![0u8; total as usize]
    }

    fn compute_rate_of_change(&self) -> Vec<i32> {
        let mut deltas = Vec::new();
        for i in 1..self.measurements.len() {
            let delta = self.measurements[i]
                .value
                .wrapping_sub(self.measurements[i - 1].value);
            let time_diff = self.measurements[i]
                .timestamp
                .wrapping_sub(self.measurements[i - 1].timestamp);
            if time_diff > 0 {
                deltas.push(delta.wrapping_mul(1000) / time_diff as i32);
            }
        }
        deltas
    }

    fn scale_reading(&self, index: usize, factor_num: i32, factor_den: i32) -> i32 {
        let val = self.measurements[index].value;
        val.wrapping_mul(factor_num) / factor_den
    }

    fn generate_report(&self) {
        println!("Sensor Array Report");
        println!("===================");
        println!("Readings: {}", self.measurements.len());
        println!("Average: {}", self.compute_average());
        println!("Calibration Offset: {}", self.calibration_offset);

        let rates = self.compute_rate_of_change();
        if !rates.is_empty() {
            let max_rate = rates.iter().copied().max().unwrap_or(0);
            let min_rate = rates.iter().copied().min().unwrap_or(0);
            println!("Rate of Change - Max: {}, Min: {}", max_rate, min_rate);
        }

        for (i, m) in self.measurements.iter().enumerate() {
            let calibrated = self.calibrated_value(i);
            println!(
                "  Sensor {} @ t={}: raw={}, calibrated={}",
                m.sensor_id, m.timestamp, m.value, calibrated
            );
        }
    }
}

fn convert_temperature(celsius_hundredths: i32) -> i32 {
    let fahrenheit = celsius_hundredths.wrapping_mul(9) / 5 + 3200;
    fahrenheit
}

fn compute_checksum(data: &[u8]) -> u8 {
    let mut sum: u8 = 0;
    for &b in data {
        sum = sum.wrapping_add(b);
    }
    sum
}

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        println!("Usage: {} <command> [args...]", args[0]);
        println!("Commands:");
        println!("  report                              Show sensor report");
        println!("  power <voltage> <current>           Compute power consumption");
        println!("  temp <celsius_hundredths>           Convert temperature");
        println!("  scale <index> <num> <den>           Scale a reading");
        println!("  alloc <count> <size>                Allocate sample buffer");
        println!("  checksum <data>                     Compute data checksum");
        process::exit(0);
    }

    let cmd = &args[1];

    match cmd.as_str() {
        "report" => {
            let mut array = SensorArray::new(150);
            array.add_reading(1, 2_000_000_000, 1000);
            array.add_reading(1, 1_500_000_000, 2000);
            array.add_reading(2, 800_000_000, 3000);
            array.add_reading(2, 1_200_000_000, 4000);
            array.add_reading(3, 500_000_000, 5000);
            array.generate_report();
        }
        "power" => {
            if args.len() < 4 {
                eprintln!("Usage: {} power <voltage> <current>", args[0]);
                process::exit(1);
            }
            let voltage: i32 = args[2].parse().unwrap_or(0);
            let current: i32 = args[3].parse().unwrap_or(0);
            let array = SensorArray::new(0);
            let power = array.compute_power_consumption(voltage, current);
            println!("Power: {} microwatts", power);
        }
        "temp" => {
            if args.len() < 3 {
                eprintln!("Usage: {} temp <celsius_hundredths>", args[0]);
                process::exit(1);
            }
            let celsius: i32 = args[2].parse().unwrap_or(0);
            let fahrenheit = convert_temperature(celsius);
            println!("Temperature: {} (F hundredths)", fahrenheit);
        }
        "scale" => {
            if args.len() < 5 {
                eprintln!("Usage: {} scale <index> <num> <den>", args[0]);
                process::exit(1);
            }
            let mut array = SensorArray::new(0);
            array.add_reading(1, 1_000_000_000, 1000);
            array.add_reading(2, 500_000_000, 2000);
            let index: usize = args[2].parse().unwrap_or(0);
            let num: i32 = args[3].parse().unwrap_or(1);
            let den: i32 = args[4].parse().unwrap_or(1);
            let result = array.scale_reading(index, num, den);
            println!("Scaled value: {}", result);
        }
        "alloc" => {
            if args.len() < 4 {
                eprintln!("Usage: {} alloc <count> <size>", args[0]);
                process::exit(1);
            }
            let count: u32 = args[2].parse().unwrap_or(0);
            let size: u32 = args[3].parse().unwrap_or(0);
            let array = SensorArray::new(0);
            let buf = array.allocate_sample_buffer(count, size);
            println!("Allocated {} bytes", buf.len());
        }
        "checksum" => {
            if args.len() < 3 {
                eprintln!("Usage: {} checksum <data>", args[0]);
                process::exit(1);
            }
            let cs = compute_checksum(args[2].as_bytes());
            println!("Checksum: 0x{:02X}", cs);
        }
        _ => {
            eprintln!("Unknown command: {}", cmd);
            process::exit(1);
        }
    }
}
