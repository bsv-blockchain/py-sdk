// Command script_oracle checks transaction scripts with GoBDK, the bitcoin-sv
// node's C++ script interpreter that Teranode validates with, so that py-sdk's
// script VMs can be compared against it.
//
// It reads one JSON request per line on stdin and writes one JSON response per
// line on stdout, in the same order:
//
//	{"id": "...", "ef": "<extended-format tx hex>", "utxo_heights": [949999], "block_height": 950000}
//	{"id": "...", "consensus": {"ok": true}, "policy": {"ok": false, "err": "..."}}
//
// Each request is verified twice: with consensus rules (a block) and with policy
// rules (the mempool), as Teranode's validator does.
package main

import (
	"bufio"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"

	bdkscript "github.com/bitcoin-sv/bdk/module/gobdk/script"
)

type request struct {
	ID          string  `json:"id"`
	EF          string  `json:"ef"`
	UtxoHeights []int32 `json:"utxo_heights"`
	BlockHeight int32   `json:"block_height"`
}

type verdict struct {
	OK  bool   `json:"ok"`
	Err string `json:"err,omitempty"`
}

type response struct {
	ID        string   `json:"id"`
	Consensus *verdict `json:"consensus,omitempty"`
	Policy    *verdict `json:"policy,omitempty"`
	Error     string   `json:"error,omitempty"` // the request could not be checked
}

func check(err error) *verdict {
	if err != nil {
		return &verdict{Err: err.Error()}
	}
	return &verdict{OK: true}
}

func main() {
	validator := bdkscript.NewTxValidator("main")
	if validator == nil {
		fmt.Fprintln(os.Stderr, "script_oracle: cannot create the GoBDK TxValidator")
		os.Exit(1)
	}

	in := bufio.NewScanner(os.Stdin)
	in.Buffer(make([]byte, 1<<20), 1<<30)
	out := json.NewEncoder(os.Stdout)

	for in.Scan() {
		var req request
		resp := response{}
		if err := json.Unmarshal(in.Bytes(), &req); err != nil {
			resp.Error = err.Error()
		} else if ef, err := hex.DecodeString(req.EF); err != nil {
			resp.ID, resp.Error = req.ID, err.Error()
		} else {
			resp.ID = req.ID
			resp.Consensus = check(validator.VerifyScript(ef, req.UtxoHeights, req.BlockHeight, true))
			resp.Policy = check(validator.VerifyScript(ef, req.UtxoHeights, req.BlockHeight, false))
		}
		if err := out.Encode(resp); err != nil {
			fmt.Fprintln(os.Stderr, "script_oracle:", err)
			os.Exit(1)
		}
	}
	if err := in.Err(); err != nil {
		fmt.Fprintln(os.Stderr, "script_oracle:", err)
		os.Exit(1)
	}
}
