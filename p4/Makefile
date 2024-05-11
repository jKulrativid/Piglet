P4_FILE_NAME = "piglet"

.PHONY: run_p4c
run_p4c:
	p4c-vitisnet -o $(P4_FILE_NAME).json $(P4_FILE_NAME).p4

.PHONY: run_bm_test
run_bm_test:
	run-p4bm-vitisnet -j $(P4_FILE_NAME).json -s cli_commands.txt
