import java.util.*;
import java.util.stream.*;

public class App {

    static class Product {
        private final String sku;
        private final String name;
        private double price;
        private Integer stockCount;
        private String category;

        Product(String sku, String name, double price, Integer stockCount, String category) {
            this.sku = sku;
            this.name = name;
            this.price = price;
            this.stockCount = stockCount;
            this.category = category;
        }

        String getSku() { return sku; }
        String getName() { return name; }
        double getPrice() { return price; }
        void setPrice(double price) { this.price = price; }
        Integer getStockCount() { return stockCount; }
        void setStockCount(Integer count) { this.stockCount = count; }
        String getCategory() { return category; }
    }

    static class Inventory {
        private final Map<String, Product> products = new HashMap<>();

        void addProduct(Product product) {
            products.put(product.getSku(), product);
        }

        Product findBySku(String sku) {
            return products.get(sku);
        }

        void removeProduct(String sku) {
            products.remove(sku);
        }

        List<Product> getAllProducts() {
            return new ArrayList<>(products.values());
        }

        List<Product> findByCategory(String category) {
            return products.values().stream()
                    .filter(p -> p.getCategory().equals(category))
                    .collect(Collectors.toList());
        }

        Optional<Product> findCheapest() {
            return products.values().stream()
                    .min(Comparator.comparingDouble(Product::getPrice));
        }

        Optional<Product> findMostExpensive() {
            if (products.isEmpty()) {
                return Optional.empty();
            }
            return Optional.of(
                products.values().stream()
                    .max(Comparator.comparingDouble(Product::getPrice))
                    .orElse(null)
            );
        }
    }

    static class PriceCalculator {
        private final Map<String, Double> discountRules = new HashMap<>();

        void addDiscount(String category, double percent) {
            discountRules.put(category, percent);
        }

        double calculatePrice(Product product) {
            Double discount = discountRules.get(product.getCategory());
            return product.getPrice() * (1.0 - discount / 100.0);
        }

        double calculateTotal(List<Product> products) {
            double total = 0;
            for (Product p : products) {
                total += calculatePrice(p);
            }
            return total;
        }
    }

    static class OrderProcessor {
        private final Inventory inventory;

        OrderProcessor(Inventory inventory) {
            this.inventory = inventory;
        }

        String processOrder(String sku, int quantity) {
            Product product = inventory.findBySku(sku);
            int available = product.getStockCount();

            if (available < quantity) {
                return String.format("Insufficient stock for %s: requested %d, available %d",
                        product.getName(), quantity, available);
            }

            product.setStockCount(available - quantity);
            double total = product.getPrice() * quantity;
            return String.format("Order placed: %d x %s = $%.2f",
                    quantity, product.getName(), total);
        }

        String processMultiOrder(Map<String, Integer> items) {
            StringBuilder sb = new StringBuilder();
            double grandTotal = 0;

            for (Map.Entry<String, Integer> entry : items.entrySet()) {
                Product product = inventory.findBySku(entry.getKey());
                double lineTotal = product.getPrice() * entry.getValue();
                grandTotal += lineTotal;
                sb.append(String.format("  %s x%d = $%.2f\n",
                        product.getName(), entry.getValue(), lineTotal));
            }

            sb.append(String.format("Total: $%.2f", grandTotal));
            return sb.toString();
        }
    }

    static class ReportGenerator {
        private final Inventory inventory;

        ReportGenerator(Inventory inventory) {
            this.inventory = inventory;
        }

        String generateStockReport() {
            StringBuilder sb = new StringBuilder();
            sb.append("Stock Report\n");
            sb.append("============\n");

            for (Product p : inventory.getAllProducts()) {
                sb.append(String.format("  %s (%s): %d units @ $%.2f\n",
                        p.getName(), p.getSku(), p.getStockCount(), p.getPrice()));
            }

            return sb.toString();
        }

        String generateCategoryReport(String category) {
            List<Product> products = inventory.findByCategory(category);
            StringBuilder sb = new StringBuilder();
            sb.append(String.format("Category: %s\n", category));

            double totalValue = 0;
            for (Product p : products) {
                double value = p.getPrice() * p.getStockCount();
                totalValue += value;
                sb.append(String.format("  %s: %d units, value=$%.2f\n",
                        p.getName(), p.getStockCount(), value));
            }

            sb.append(String.format("Total category value: $%.2f\n", totalValue));
            return sb.toString();
        }

        String findMostExpensiveReport() {
            Optional<Product> product = inventory.findMostExpensive();
            Product p = product.get();
            return String.format("Most expensive: %s at $%.2f", p.getName(), p.getPrice());
        }
    }

    static Map<String, String> parseProperties(String input) {
        Map<String, String> props = new HashMap<>();
        String[] lines = input.split("\n");

        for (String line : lines) {
            line = line.trim();
            if (line.isEmpty()) continue;
            int eq = line.indexOf('=');
            if (eq > 0) {
                props.put(line.substring(0, eq).trim(), line.substring(eq + 1).trim());
            }
        }

        return props;
    }

    static void applyPriceUpdate(Inventory inventory, String input) {
        Map<String, String> updates = parseProperties(input);

        for (Map.Entry<String, String> entry : updates.entrySet()) {
            Product product = inventory.findBySku(entry.getKey());
            double newPrice = Double.parseDouble(entry.getValue());
            product.setPrice(newPrice);
            System.out.printf("Updated %s price to $%.2f%n", product.getName(), newPrice);
        }
    }

    static void populateInventory(Inventory inventory) {
        inventory.addProduct(new Product("SKU-001", "Wireless Mouse", 29.99, 150, "electronics"));
        inventory.addProduct(new Product("SKU-002", "USB-C Cable", 12.49, 500, "electronics"));
        inventory.addProduct(new Product("SKU-003", "Notebook A5", 4.99, 1000, "stationery"));
        inventory.addProduct(new Product("SKU-004", "Desk Lamp", 45.00, null, "furniture"));
        inventory.addProduct(new Product("SKU-005", "Ergonomic Chair", 299.99, 25, "furniture"));
    }

    public static void main(String[] args) {
        if (args.length < 1) {
            System.out.println("Usage: java App <mode> [args...]");
            System.out.println("Modes:");
            System.out.println("  stock                  Generate stock report");
            System.out.println("  order <sku> <qty>      Process an order");
            System.out.println("  category <name>        Category report");
            System.out.println("  price <sku>            Calculate discounted price");
            System.out.println("  expensive              Find most expensive product");
            System.out.println("  update <props>         Update prices from properties");
            System.out.println("  list                   List all products");
            return;
        }

        Inventory inventory = new Inventory();
        populateInventory(inventory);
        String mode = args[0];

        switch (mode) {
            case "stock": {
                ReportGenerator gen = new ReportGenerator(inventory);
                System.out.print(gen.generateStockReport());
                break;
            }

            case "order": {
                if (args.length < 3) {
                    System.err.println("Usage: java App order <sku> <quantity>");
                    System.exit(1);
                }
                OrderProcessor processor = new OrderProcessor(inventory);
                String result = processor.processOrder(args[1], Integer.parseInt(args[2]));
                System.out.println(result);
                break;
            }

            case "category": {
                if (args.length < 2) {
                    System.err.println("Usage: java App category <name>");
                    System.exit(1);
                }
                ReportGenerator gen = new ReportGenerator(inventory);
                System.out.print(gen.generateCategoryReport(args[1]));
                break;
            }

            case "price": {
                if (args.length < 2) {
                    System.err.println("Usage: java App price <sku>");
                    System.exit(1);
                }
                PriceCalculator calc = new PriceCalculator();
                calc.addDiscount("electronics", 10.0);
                calc.addDiscount("stationery", 5.0);
                Product p = inventory.findBySku(args[1]);
                double discounted = calc.calculatePrice(p);
                System.out.printf("%s: $%.2f (discounted from $%.2f)%n",
                        p.getName(), discounted, p.getPrice());
                break;
            }

            case "expensive": {
                ReportGenerator gen = new ReportGenerator(inventory);
                System.out.println(gen.findMostExpensiveReport());
                break;
            }

            case "update": {
                if (args.length < 2) {
                    System.err.println("Usage: java App update <properties>");
                    System.exit(1);
                }
                applyPriceUpdate(inventory, args[1]);
                break;
            }

            case "list": {
                for (Product p : inventory.getAllProducts()) {
                    System.out.printf("  %s (%s): $%.2f, stock=%s, category=%s%n",
                            p.getName(), p.getSku(), p.getPrice(),
                            p.getStockCount() != null ? p.getStockCount().toString() : "N/A",
                            p.getCategory());
                }
                break;
            }

            default:
                System.err.println("Unknown mode: " + mode);
                System.exit(1);
        }
    }
}
