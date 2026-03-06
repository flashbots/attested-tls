.PHONY: benchmarks

WARMUP      ?= 1
MEASUREMENT ?= 30
SAMPLES     ?= 50

benchmarks:
	cargo bench -p nested-tls --bench throughput -- --warm-up-time $(WARMUP) --measurement-time $(MEASUREMENT) --sample-size $(SAMPLES)
