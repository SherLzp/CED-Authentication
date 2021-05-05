package sm9

import (
	"fmt"
	"testing"
)

func TestKDF(t *testing.T) {
	kdf := KDF([]byte("1"), 32)
	fmt.Println(kdf)
	mac := MAC([]byte("1111"), []byte("222"))
	fmt.Println(mac)
}
