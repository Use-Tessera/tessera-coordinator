// Command agent is a testnet demo of an AI agent paying for an API from a
// Tessera group account.
//
// The paid API answers 402 Payment Required with a price. The agent, which
// holds only the coordinator's API token, has the group sign a Soroban
// authorization for the XLM contract's transfer to the API, and sends it back.
// The API checks the payee and amount, submits the transaction (paying the
// fee itself), and serves the response. Every signer judges each payment
// against its own policy, so the agent spends only what the policy allows,
// whatever it is told to do.
//
// Run scripts/agent-demo.sh rather than this command directly.
package main

import (
	"errors"
	"fmt"
	"os"

	"github.com/stellar/go-stellar-sdk/keypair"
	"github.com/stellar/go-stellar-sdk/network"
	"github.com/stellar/go-stellar-sdk/strkey"
	"github.com/stellar/go-stellar-sdk/xdr"
)

const passphrase = network.TestNetworkPassphrase

// stroopsPerXLM is the XLM contract's unit: it has 7 decimals.
const stroopsPerXLM = 10_000_000

const usage = `agent runs the agent-pays-for-an-API demo on testnet.

Usage:
  agent newkey                 print a new SECRET and ADDRESS
  agent paywall [flags]        the paid API; PAYWALL_SECRET holds its key
  agent run     [flags]        the agent; TESSERA_API_TOKEN holds its token
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "newkey":
		kp, kerr := keypair.Random()
		if kerr == nil {
			fmt.Println(kp.Seed(), kp.Address())
		}
		err = kerr
	case "paywall":
		err = runPaywall(os.Args[2:])
	case "run":
		err = runAgent(os.Args[2:])
	default:
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

// xlm returns the testnet XLM contract's address and its C... form.
func xlm() (xdr.ScAddress, string, error) {
	id, err := xdr.MustNewNativeAsset().ContractID(passphrase)
	if err != nil {
		return xdr.ScAddress{}, "", err
	}
	cid := xdr.ContractId(id)
	s, err := strkey.Encode(strkey.VersionByteContract, id[:])
	if err != nil {
		return xdr.ScAddress{}, "", err
	}
	return xdr.ScAddress{Type: xdr.ScAddressTypeScAddressTypeContract, ContractId: &cid}, s, nil
}

func accountVal(g string) (xdr.ScVal, error) {
	var id xdr.AccountId
	if err := id.SetAddress(g); err != nil {
		return xdr.ScVal{}, fmt.Errorf("account %q: %w", g, err)
	}
	return xdr.ScVal{Type: xdr.ScValTypeScvAddress, Address: &xdr.ScAddress{Type: xdr.ScAddressTypeScAddressTypeAccount, AccountId: &id}}, nil
}

// transfer is the token call transfer(from, to, amount).
func transfer(token xdr.ScAddress, from, to string, stroops int64) (xdr.InvokeContractArgs, error) {
	if stroops <= 0 {
		return xdr.InvokeContractArgs{}, errors.New("amount must be positive")
	}
	f, err := accountVal(from)
	if err != nil {
		return xdr.InvokeContractArgs{}, err
	}
	t, err := accountVal(to)
	if err != nil {
		return xdr.InvokeContractArgs{}, err
	}
	amount := xdr.ScVal{Type: xdr.ScValTypeScvI128, I128: &xdr.Int128Parts{Lo: xdr.Uint64(stroops)}} //nolint:gosec // G115: positive, checked above
	return xdr.InvokeContractArgs{ContractAddress: token, FunctionName: "transfer", Args: xdr.ScVec{f, t, amount}}, nil
}

func invoke(call xdr.InvokeContractArgs) xdr.HostFunction {
	return xdr.HostFunction{Type: xdr.HostFunctionTypeHostFunctionTypeInvokeContract, InvokeContract: &call}
}

func short(s string) string {
	if len(s) <= 12 {
		return s
	}
	return s[:6] + "…" + s[len(s)-4:]
}
