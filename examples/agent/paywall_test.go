package main

import (
	"testing"

	"github.com/stellar/go-stellar-sdk/keypair"
	"github.com/stellar/go-stellar-sdk/xdr"
)

const price = 1 * stroopsPerXLM

func payment(t *testing.T, token xdr.ScAddress, from, to string, stroops int64) xdr.SorobanAuthorizationEntry {
	t.Helper()
	call, err := transfer(token, from, to, stroops)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := accountVal(from)
	if err != nil {
		t.Fatal(err)
	}
	return xdr.SorobanAuthorizationEntry{
		Credentials: xdr.SorobanCredentials{
			Type:    xdr.SorobanCredentialsTypeSorobanCredentialsAddress,
			Address: &xdr.SorobanAddressCredentials{Address: *signer.Address, Nonce: 7, SignatureExpirationLedger: 100},
		},
		RootInvocation: xdr.SorobanAuthorizedInvocation{
			Function: xdr.SorobanAuthorizedFunction{
				Type:       xdr.SorobanAuthorizedFunctionTypeSorobanAuthorizedFunctionTypeContractFn,
				ContractFn: &call,
			},
		},
	}
}

func TestCheckPayment(t *testing.T) {
	asset, _, err := xlm()
	if err != nil {
		t.Fatal(err)
	}
	other := xdr.ContractId{1}
	otherToken := xdr.ScAddress{Type: xdr.ScAddressTypeScAddressTypeContract, ContractId: &other}
	group, payTo, stranger := keypair.MustRandom().Address(), keypair.MustRandom().Address(), keypair.MustRandom().Address()

	if _, err := checkPayment(payment(t, asset, group, payTo, price), asset, payTo, price); err != nil {
		t.Fatalf("exact payment refused: %v", err)
	}

	withSub := payment(t, asset, group, payTo, price)
	withSub.RootInvocation.SubInvocations = []xdr.SorobanAuthorizedInvocation{payment(t, asset, group, stranger, price).RootInvocation}

	notOwnFunds := payment(t, asset, group, payTo, price)
	strangerVal, _ := accountVal(stranger)
	notOwnFunds.Credentials.Address.Address = *strangerVal.Address

	sourceCreds := payment(t, asset, group, payTo, price)
	sourceCreds.Credentials = xdr.SorobanCredentials{Type: xdr.SorobanCredentialsTypeSorobanCredentialsSourceAccount}

	for name, e := range map[string]xdr.SorobanAuthorizationEntry{
		"wrong payee":          payment(t, asset, group, stranger, price),
		"too little":           payment(t, asset, group, payTo, price-1),
		"too much":             payment(t, asset, group, payTo, price+1),
		"wrong token":          payment(t, otherToken, group, payTo, price),
		"extra sub-invocation": withSub,
		"someone else's funds": notOwnFunds,
		"source-account creds": sourceCreds,
	} {
		if _, err := checkPayment(e, asset, payTo, price); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
