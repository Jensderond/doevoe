package delivery

import (
	"errors"
	"net"
	"testing"

	"github.com/emersion/go-smtp"
)

func TestClassify(t *testing.T) {
	cases := []struct {
		err  error
		want Class
	}{
		{&smtp.SMTPError{Code: 550, Message: "no such user"}, ClassPerm},
		{&smtp.SMTPError{Code: 451, Message: "try later"}, ClassTemp},
		{&net.DNSError{Err: "no such host", IsNotFound: true}, ClassPerm},
		{&net.DNSError{Err: "timeout", IsTimeout: true}, ClassTemp},
		{errors.New("dial tcp: connection refused"), ClassTemp},
	}
	for _, c := range cases {
		if got := Classify(c.err); got != c.want {
			t.Errorf("Classify(%v) = %v, want %v", c.err, got, c.want)
		}
	}
}
