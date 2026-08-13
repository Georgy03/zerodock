IMAGE ?= zerodock-enclave:latest
EIF ?= scanner.eif
DOCKER ?= docker
NITRO_CLI ?= nitro-cli
REPORTS_DIR ?= reports
SCANNER_VERSION ?= dev
SUPABASE_SECRET_ARN ?=

.PHONY: eif
eif:
	mkdir -p "$(dir $(EIF))"
	@echo "Building scanner version $(SCANNER_VERSION)"
	$(DOCKER) build --platform linux/amd64 -f deploy/Dockerfile \
		--build-arg SCANNER_VERSION="$(SCANNER_VERSION)" \
		--build-arg SUPABASE_SECRET_ARN="$(SUPABASE_SECRET_ARN)" \
		-t "$(IMAGE)" .
	@echo "Building $(EIF); nitro-cli will print the enclave PCR measurements below."
	$(NITRO_CLI) build-enclave --docker-uri "$(IMAGE)" --output-file "$(EIF)" | tee "$(EIF).measurements.json"

# run-enclave builds the EIF (if needed) and then runs the full real
# cycle: start the parent-side vsock-proxy/credential/report-collector
# helpers, launch the enclave without --debug-mode (so PCRs are real, not
# zeroed), wait for its report to arrive, and tear the helpers (and the
# enclave) back down. Run this on the parent EC2 instance, not your
# laptop — it needs docker, nitro-cli, and actual Nitro Enclave-capable
# hardware. See deploy/run-enclave.sh for the actual orchestration.
.PHONY: run-enclave
run-enclave: eif
	REPORTS_DIR="$(REPORTS_DIR)" deploy/run-enclave.sh "$(EIF)"
