package main

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

type Metric struct {
	Name      string
	Value     float64
	Tags      map[string]string
	Timestamp int64
}

type MetricStore struct {
	metrics map[string]*Metric
	history map[string][]*Metric
}

func NewMetricStore() *MetricStore {
	return &MetricStore{
		metrics: make(map[string]*Metric),
		history: make(map[string][]*Metric),
	}
}

func (s *MetricStore) Record(name string, value float64, ts int64, tags map[string]string) {
	m := &Metric{
		Name:      name,
		Value:     value,
		Tags:      tags,
		Timestamp: ts,
	}
	s.metrics[name] = m
	s.history[name] = append(s.history[name], m)
}

func (s *MetricStore) Get(name string) *Metric {
	return s.metrics[name]
}

func (s *MetricStore) Delete(name string) {
	delete(s.metrics, name)
	delete(s.history, name)
}

func (s *MetricStore) Names() []string {
	names := make([]string, 0, len(s.metrics))
	for k := range s.metrics {
		names = append(names, k)
	}
	return names
}

type Aggregator struct {
	store *MetricStore
}

func NewAggregator(store *MetricStore) *Aggregator {
	return &Aggregator{store: store}
}

func (a *Aggregator) Sum(names []string) float64 {
	total := 0.0
	for _, name := range names {
		m := a.store.Get(name)
		total += m.Value
	}
	return total
}

func (a *Aggregator) Max(names []string) *Metric {
	var best *Metric
	for _, name := range names {
		m := a.store.Get(name)
		if best == nil || m.Value > best.Value {
			best = m
		}
	}
	return best
}

type Dashboard struct {
	widgets map[string]func() string
}

func NewDashboard() *Dashboard {
	return &Dashboard{
		widgets: make(map[string]func() string),
	}
}

func (d *Dashboard) AddWidget(name string, render func() string) {
	d.widgets[name] = render
}

func (d *Dashboard) Render(name string) string {
	fn := d.widgets[name]
	return fn()
}

func (d *Dashboard) RenderAll() string {
	var sb strings.Builder
	for name, fn := range d.widgets {
		sb.WriteString(fmt.Sprintf("=== %s ===\n", name))
		sb.WriteString(fn())
		sb.WriteString("\n")
	}
	return sb.String()
}

func parseMetricLine(line string) *Metric {
	parts := strings.Fields(line)
	if len(parts) < 3 {
		return nil
	}

	name := parts[0]
	value, err := strconv.ParseFloat(parts[1], 64)
	if err != nil {
		return nil
	}
	ts, err := strconv.ParseInt(parts[2], 10, 64)
	if err != nil {
		return nil
	}

	tags := make(map[string]string)
	for _, part := range parts[3:] {
		kv := strings.SplitN(part, "=", 2)
		if len(kv) == 2 {
			tags[kv[0]] = kv[1]
		}
	}

	return &Metric{
		Name:      name,
		Value:     value,
		Tags:      tags,
		Timestamp: ts,
	}
}

func ingestData(store *MetricStore, data string) {
	lines := strings.Split(data, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		m := parseMetricLine(line)
		store.Record(m.Name, m.Value, m.Timestamp, m.Tags)
	}
}

func compareMetrics(store *MetricStore, name1, name2 string) {
	m1 := store.Get(name1)
	m2 := store.Get(name2)

	diff := m1.Value - m2.Value
	fmt.Printf("%s (%.2f) vs %s (%.2f): diff = %.2f\n",
		name1, m1.Value, name2, m2.Value, diff)
}

func getTagValue(store *MetricStore, metricName, tagKey string) string {
	m := store.Get(metricName)
	if m == nil {
		return ""
	}
	return m.Tags[tagKey]
}

func buildReport(store *MetricStore) string {
	var sb strings.Builder
	sb.WriteString("Metrics Report\n")
	sb.WriteString("==============\n")

	for _, name := range store.Names() {
		m := store.Get(name)
		sb.WriteString(fmt.Sprintf("  %s: %.2f (ts=%d)\n", m.Name, m.Value, m.Timestamp))
		if len(m.Tags) > 0 {
			for k, v := range m.Tags {
				sb.WriteString(fmt.Sprintf("    %s=%s\n", k, v))
			}
		}
	}

	return sb.String()
}

func filterByTag(store *MetricStore, tagKey, tagValue string) []*Metric {
	var results []*Metric
	for _, name := range store.Names() {
		m := store.Get(name)
		if m.Tags[tagKey] == tagValue {
			results = append(results, m)
		}
	}
	return results
}

func populateStore(store *MetricStore) {
	store.Record("cpu_usage", 72.5, 1700000001, map[string]string{"host": "web-01", "region": "us-east"})
	store.Record("memory_used", 4096.0, 1700000002, map[string]string{"host": "web-01", "unit": "MB"})
	store.Record("disk_io", 150.3, 1700000003, map[string]string{"host": "db-01", "device": "sda"})
	store.Record("request_rate", 1250.0, 1700000004, map[string]string{"host": "web-01", "endpoint": "/api"})
	store.Record("error_rate", 3.2, 1700000005, map[string]string{"host": "web-01", "level": "warn"})
}

func main() {
	if len(os.Args) < 2 {
		fmt.Printf("Usage: %s <mode> [args...]\n", os.Args[0])
		fmt.Println("Modes:")
		fmt.Println("  report                  Generate metrics report")
		fmt.Println("  compare <m1> <m2>       Compare two metrics")
		fmt.Println("  sum <m1,m2,...>          Sum metric values")
		fmt.Println("  max <m1,m2,...>          Find max metric")
		fmt.Println("  ingest <data>           Ingest metric data")
		fmt.Println("  filter <tag> <value>    Filter metrics by tag")
		fmt.Println("  dashboard               Render dashboard")
		fmt.Println("  list                    List all metrics")
		return
	}

	store := NewMetricStore()
	populateStore(store)
	mode := os.Args[1]

	switch mode {
	case "report":
		fmt.Print(buildReport(store))

	case "compare":
		if len(os.Args) < 4 {
			fmt.Fprintf(os.Stderr, "Usage: %s compare <metric1> <metric2>\n", os.Args[0])
			os.Exit(1)
		}
		compareMetrics(store, os.Args[2], os.Args[3])

	case "sum":
		if len(os.Args) < 3 {
			fmt.Fprintf(os.Stderr, "Usage: %s sum <metric1,metric2,...>\n", os.Args[0])
			os.Exit(1)
		}
		names := strings.Split(os.Args[2], ",")
		agg := NewAggregator(store)
		total := agg.Sum(names)
		fmt.Printf("Sum: %.2f\n", total)

	case "max":
		if len(os.Args) < 3 {
			fmt.Fprintf(os.Stderr, "Usage: %s max <metric1,metric2,...>\n", os.Args[0])
			os.Exit(1)
		}
		names := strings.Split(os.Args[2], ",")
		agg := NewAggregator(store)
		best := agg.Max(names)
		fmt.Printf("Max: %s = %.2f\n", best.Name, best.Value)

	case "ingest":
		if len(os.Args) < 3 {
			fmt.Fprintf(os.Stderr, "Usage: %s ingest <data>\n", os.Args[0])
			os.Exit(1)
		}
		ingestData(store, os.Args[2])
		fmt.Print(buildReport(store))

	case "filter":
		if len(os.Args) < 4 {
			fmt.Fprintf(os.Stderr, "Usage: %s filter <tag> <value>\n", os.Args[0])
			os.Exit(1)
		}
		results := filterByTag(store, os.Args[2], os.Args[3])
		for _, m := range results {
			fmt.Printf("  %s: %.2f\n", m.Name, m.Value)
		}

	case "dashboard":
		dash := NewDashboard()
		dash.AddWidget("summary", func() string {
			return buildReport(store)
		})
		dash.AddWidget("alerts", func() string {
			m := store.Get("error_rate")
			if m.Value > 5.0 {
				return "HIGH ERROR RATE"
			}
			return "OK"
		})
		fmt.Print(dash.RenderAll())
		fmt.Println("--- Rendering missing widget ---")
		fmt.Println(dash.Render("nonexistent"))

	case "list":
		for _, name := range store.Names() {
			m := store.Get(name)
			fmt.Printf("  %s: %.2f\n", m.Name, m.Value)
		}

	default:
		fmt.Fprintf(os.Stderr, "Unknown mode: %s\n", mode)
		os.Exit(1)
	}
}
