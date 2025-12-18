package handler

import (
	//"github.com/golang-jwt/jwt/v5"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"
)

type Token struct {
	Type              string
	Raw               string
	JWT               map[string]string
	Scopes            []string
	AccessToken       string
	AccessExpireTime  time.Time
	RefreshToken      string
	RefreshExpireTime time.Time
}

func convertExpiration(data any) (time.Time, error) {
	var exp time.Time
	fexp, ok := data.(float64)
	if !ok {
		return exp, Fatalf("float64 conversion failed")
	}
	iexp := int64(math.Round(fexp))
	exp = time.Now().Add(time.Duration(iexp) * time.Second)
	return exp, nil
}

func NewToken(data map[string]any) (*Token, error) {

	jwt, err := DecodeJWT(data["id_token"].(string))
	if err != nil {
		return nil, Fatal(err)
	}
	aexp, err := convertExpiration(data["expires_in"])
	if err != nil {
		return nil, Fatal(err)
	}
	rexp, err := convertExpiration(data["refresh_token_expires_in"])
	if err != nil {
		return nil, Fatal(err)
	}

	t := Token{
		Type:              data["token_type"].(string),
		AccessToken:       data["access_token"].(string),
		AccessExpireTime:  aexp,
		RefreshToken:      data["refresh_token"].(string),
		RefreshExpireTime: rexp,
		Scopes:            strings.Split(data["scope"].(string), " "),
		Raw:               data["id_token"].(string),
		JWT:               jwt,
	}
	return &t, nil
}

func DecodeJWT(tokenString string) (map[string]string, error) {
	parts := strings.Split(tokenString, ".")
	if len(parts) != 3 {
		return nil, Fatalf("invalid token format")
	}
	payload := parts[1]
	decodedPayload, err := base64.RawURLEncoding.DecodeString(payload)
	if err != nil {
		return nil, Fatal(err)
	}
	claims := make(map[string]any)
	err = json.Unmarshal(decodedPayload, &claims)
	if err != nil {
		return nil, Fatal(err)
	}
	/*
			// FIXME: properly validate with google's pubkey
			token, err := jwt.Parse(tokenString, nil)
			if err != nil {
				return nil, Fatal(err)
			}
			claims, ok := token.Claims.(jwt.MapClaims)
			if !ok || !token.Valid {
				return nil, Fatalf("invalid token claims")
			}

		claims := jwt.MapClaims{}
		_, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
			return nil, nil
		})
		if err != nil {
			return nil, Fatal(err)
		}
	*/

	result := make(map[string]string)
	for key, value := range claims {
		switch t := value.(type) {
		case string:
			result[key] = value.(string)
		case int, int64:
			result[key] = strconv.FormatInt(value.(int64), 10)
		case float64:
			result[key] = strconv.FormatFloat(value.(float64), 'E', -1, 64)
		case bool:
			result[key] = fmt.Sprintf("%v", value.(bool))
		default:
			return nil, Fatalf("unexpected data type: %+v", t)
		}
	}
	return result, nil
}
