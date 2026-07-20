package delivery

import (
	"errors"
	"net"

	"github.com/emersion/go-smtp"
)

type Class int

const (
	ClassTemp Class = iota
	ClassPerm
)

func Classify(err error) Class {
	var se *smtp.SMTPError
	if errors.As(err, &se) {
		if se.Code >= 500 {
			return ClassPerm
		}
		return ClassTemp
	}
	var de *net.DNSError
	if errors.As(err, &de) && de.IsNotFound {
		return ClassPerm // recipient domain doesn't exist: the typo case
	}
	return ClassTemp
}
