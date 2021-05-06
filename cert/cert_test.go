package cert

import (
	"fmt"
	"testing"
)

func TestCreateCert(t *testing.T) {
	certificate, _, key := GenCARoot()
	dca, _, _ := GenDCA("test", certificate, key)
	b := VerifyDCA(certificate, dca)
	fmt.Println(b)
}
