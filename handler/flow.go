package handler

type Flow struct {
	Local        string
	Gmail        string
	JWT          string
	AuthToken    string
	RefreshToken string
	Nonce        *Nonce
}

func NewFlow() (*Flow, error) {
	nonce, err := NewNonce()
	if err != nil {
		return nil, Fatal(err)
	}
	flow := Flow{
		Nonce: nonce,
	}
	return &flow, nil
}
