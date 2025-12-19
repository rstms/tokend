package handler

import (
	"github.com/google/uuid"
	"time"
)

type Nonce struct {
	Id           uuid.UUID
	Text         string
	Created      time.Time
	LocalAddress string
}

func NewNonce(localAddress string) (*Nonce, error) {
	nid, err := uuid.NewV7()
	if err != nil {
		return nil, Fatal(err)
	}
	nonceData, err := nid.MarshalText()
	if err != nil {
		return nil, Fatal(err)
	}
	n := Nonce{
		Id:           nid,
		Text:         string(nonceData),
		Created:      time.Now(),
		LocalAddress: localAddress,
	}
	return &n, nil
}
