import java.util.ArrayList;
import java.util.List;

public class App {

    static class TimeEntry {
        String employee;
        int hoursWorked;
        int hourlyRateCents;
        int overtimeMultiplierPct;

        TimeEntry(String employee, int hours, int rate, int overtimePct) {
            this.employee = employee;
            this.hoursWorked = hours;
            this.hourlyRateCents = rate;
            this.overtimeMultiplierPct = overtimePct;
        }
    }

    static class PayrollEngine {
        private List<TimeEntry> entries = new ArrayList<>();
        private int taxRateBP;

        PayrollEngine(int taxRateBP) {
            this.taxRateBP = taxRateBP;
        }

        void addEntry(String employee, int hours, int rate, int overtimePct) {
            entries.add(new TimeEntry(employee, hours, rate, overtimePct));
        }

        int computeGrossPay(TimeEntry entry) {
            int regularHours = Math.min(entry.hoursWorked, 40);
            int overtimeHours = Math.max(entry.hoursWorked - 40, 0);
            int regularPay = regularHours * entry.hourlyRateCents;
            int overtimePay = overtimeHours * entry.hourlyRateCents
                    * entry.overtimeMultiplierPct / 100;
            return regularPay + overtimePay;
        }

        int computeTax(int grossCents) {
            return grossCents * taxRateBP / 10000;
        }

        int computeNetPay(TimeEntry entry) {
            int gross = computeGrossPay(entry);
            int tax = computeTax(gross);
            return gross - tax;
        }

        int computeTotalPayroll() {
            int total = 0;
            for (TimeEntry entry : entries) {
                total += computeGrossPay(entry);
            }
            return total;
        }

        int computeBonus(int baseSalary, int performanceScore) {
            int bonusPct = performanceScore * 5;
            if (bonusPct > 50) bonusPct = 50;
            return baseSalary * bonusPct / 100;
        }

        byte[] allocatePaystubBuffer(int employeeCount, int bytesPerStub) {
            int totalSize = employeeCount * bytesPerStub;
            if (totalSize < 0) {
                return null;
            }
            return new byte[totalSize];
        }

        short computePaycheckNumber(short lastNumber, short increment) {
            return (short) (lastNumber + increment);
        }

        int computeRetirementContribution(int annualSalary, int matchPct,
                                           int employeeContribPct) {
            int employeeContrib = annualSalary * employeeContribPct / 100;
            int employerMatch = employeeContrib * matchPct / 100;
            return employeeContrib + employerMatch;
        }

        void generatePayrollReport() {
            System.out.println("Payroll Report");
            System.out.println("==============");

            int totalGross = 0;
            int totalNet = 0;

            for (int i = 0; i < entries.size(); i++) {
                TimeEntry e = entries.get(i);
                int gross = computeGrossPay(e);
                int net = computeNetPay(e);
                totalGross += gross;
                totalNet += net;

                System.out.printf("  %d. %s: %d hrs @ %d cents/hr | Gross: %d | Net: %d%n",
                        i + 1, e.employee, e.hoursWorked, e.hourlyRateCents,
                        gross, net);
            }

            System.out.printf("Total Gross: $%d.%02d%n",
                    totalGross / 100, Math.abs(totalGross % 100));
            System.out.printf("Total Net:   $%d.%02d%n",
                    totalNet / 100, Math.abs(totalNet % 100));
        }
    }

    public static void main(String[] args) {
        if (args.length < 1) {
            System.out.println("Usage: App <command> [args...]");
            System.out.println("Commands:");
            System.out.println("  payroll                              Show payroll report");
            System.out.println("  bonus <salary> <score>               Compute bonus");
            System.out.println("  retire <salary> <match%> <contrib%>  Retirement contribution");
            System.out.println("  alloc <count> <size>                 Allocate paystub buffer");
            System.out.println("  checknum <last> <increment>          Next paycheck number");
            System.out.println("  grosspay <hours> <rate> <ot_pct>     Compute gross pay");
            System.exit(0);
        }

        String cmd = args[0];
        PayrollEngine engine = new PayrollEngine(2200);

        switch (cmd) {
            case "payroll":
                engine.addEntry("Maria Garcia", 80, 75000, 150);
                engine.addEntry("James Wilson", 60, 95000, 200);
                engine.addEntry("Sarah Chen", 45, 120000, 150);
                engine.addEntry("David Kim", 168, 45000, 150);
                engine.generatePayrollReport();
                System.out.printf("Total Payroll: %d cents%n", engine.computeTotalPayroll());
                break;

            case "bonus":
                if (args.length < 3) {
                    System.err.println("Usage: App bonus <salary> <score>");
                    System.exit(1);
                }
                int salary = Integer.parseInt(args[1]);
                int score = Integer.parseInt(args[2]);
                int bonus = engine.computeBonus(salary, score);
                System.out.printf("Bonus: %d cents%n", bonus);
                break;

            case "retire":
                if (args.length < 4) {
                    System.err.println("Usage: App retire <salary> <match%> <contrib%>");
                    System.exit(1);
                }
                int annualSalary = Integer.parseInt(args[1]);
                int matchPct = Integer.parseInt(args[2]);
                int contribPct = Integer.parseInt(args[3]);
                int contrib = engine.computeRetirementContribution(
                        annualSalary, matchPct, contribPct);
                System.out.printf("Total retirement contribution: %d cents%n", contrib);
                break;

            case "alloc":
                if (args.length < 3) {
                    System.err.println("Usage: App alloc <count> <size>");
                    System.exit(1);
                }
                int count = Integer.parseInt(args[1]);
                int size = Integer.parseInt(args[2]);
                byte[] buf = engine.allocatePaystubBuffer(count, size);
                if (buf != null) {
                    System.out.printf("Allocated %d bytes for %d paystubs%n",
                            buf.length, count);
                } else {
                    System.err.println("Allocation failed");
                }
                break;

            case "checknum":
                if (args.length < 3) {
                    System.err.println("Usage: App checknum <last> <increment>");
                    System.exit(1);
                }
                short last = Short.parseShort(args[1]);
                short incr = Short.parseShort(args[2]);
                short next = engine.computePaycheckNumber(last, incr);
                System.out.printf("Next paycheck number: %d%n", next);
                break;

            case "grosspay":
                if (args.length < 4) {
                    System.err.println("Usage: App grosspay <hours> <rate> <ot_pct>");
                    System.exit(1);
                }
                int hours = Integer.parseInt(args[1]);
                int rate = Integer.parseInt(args[2]);
                int otPct = Integer.parseInt(args[3]);
                TimeEntry te = new TimeEntry("CLI User", hours, rate, otPct);
                int gross = engine.computeGrossPay(te);
                System.out.printf("Gross pay: %d cents%n", gross);
                break;

            default:
                System.err.println("Unknown command: " + cmd);
                System.exit(1);
        }
    }
}
