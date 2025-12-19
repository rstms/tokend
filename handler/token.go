package handler

import (
	//"github.com/golang-jwt/jwt/v5"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/google/uuid"
	"log"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

type Token struct {
	Id                string
	LocalAddress      string
	GmailAddress      string
	Type              string
	Raw               string
	JWT               map[string]string
	Scopes            []string
	AccessToken       string
	AccessExpireTime  time.Time
	RefreshToken      string
	RefreshExpireTime time.Time
}

func NewId() (string, error) {
	id, err := uuid.NewV7()
	if err != nil {
		return "", Fatal(err)
	}
	text, err := id.MarshalText()
	if err != nil {
		return "", Fatal(err)
	}
	return string(text), nil
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

func NewToken(localAddress string, data map[string]any) (*Token, error) {
	tid, err := NewId()
	if err != nil {
		return nil, Fatal(err)
	}
	t := Token{
		Id:           tid,
		LocalAddress: localAddress,
	}
	log.Printf("created token %s for %s\n", tid, localAddress)
	err = t.ParseResponse(data)
	if err != nil {
		return nil, Fatal(err)
	}
	return &t, nil

}

func (t *Token) ParseResponse(data map[string]any) error {

	for key, value := range data {
		switch key {
		case "token_type":
			t.Type = value.(string)
		case "id_token":
			t.Raw = value.(string)
		case "access_token":
			t.AccessToken = value.(string)
		case "refresh_token":
			t.RefreshToken = value.(string)
		case "expires_in":
			exp, err := convertExpiration(value)
			if err != nil {
				return Fatal(err)
			}
			t.AccessExpireTime = exp
		case "refresh_token_expires_in":
			exp, err := convertExpiration(value)
			if err != nil {
				return Fatal(err)
			}
			t.RefreshExpireTime = exp
		case "scope":
			t.Scopes = strings.Split(value.(string), " ")
		default:
			Warning("unexpected key: %s\n", key)
		}
	}

	jwt, err := DecodeJWT(t.Raw)
	if err != nil {
		return Fatal(err)
	}
	t.JWT = jwt
	t.GmailAddress = jwt["email"]

	err = WriteToken(t)
	if err != nil {
		return Fatal(err)
	}
	return nil
}

func (t *Token) IsAccessTokenExpired() bool {
	return time.Now().After(t.AccessExpireTime)
}

func (t *Token) IsRefreshTokenExpired() bool {
	return time.Now().After(t.RefreshExpireTime)
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

	// TODO: validate JWT with google's pubkey

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

func LogTokens(tokenMap map[string]*Token) {
	logTokens := make(map[string]map[string]any)
	for id, token := range tokenMap {
		logTokens[id] = map[string]any{
			"local":             token.LocalAddress,
			"gmail":             token.GmailAddress,
			"Access":            maskToken(token.AccessToken),
			"AccessExpiration":  token.AccessExpireTime,
			"Refresh":           maskToken(token.RefreshToken),
			"RefreshExpiration": token.RefreshExpireTime,
			"Scopes":            len(token.Scopes),
		}
	}
	log.Println(FormatJSON(logTokens))
}

func maskToken(token string) string {
	var prefix string
	var suffix string
	var center string
	if len(token) > 4 {
		prefix = token[:4]
		center = "..."
	}
	if len(token) > 8 {
		suffix = token[len(token)-4:]
	}
	return prefix + center + suffix
}

func tokenCacheDir() (string, error) {
	dir, err := os.UserCacheDir()
	if err != nil {
		return "", Fatal(err)
	}
	ViperSetDefault("cache_dir", filepath.Join(dir, "tokend"))
	cacheDir := filepath.Join(ViperGetString("cache_dir"), "tokens")
	if !IsDir(cacheDir) {
		err := os.MkdirAll(cacheDir, 0700)
		if err != nil {
			return "", Fatal(err)
		}
	}
	err = os.Chmod(cacheDir, 0700)
	if err != nil {
		return "", Fatal(err)
	}
	return cacheDir, nil
}

func tokenFilename(token *Token) (string, error) {
	tokenDir, err := tokenCacheDir()
	if err != nil {
		return "", Fatal(err)
	}
	tokenFile := filepath.Join(tokenDir, token.Id+".json")
	return tokenFile, nil
}

func DeleteToken(token *Token) error {
	log.Printf("deleting token %s\n", token.Id)
	tokenFile, err := tokenFilename(token)
	if err != nil {
		return Fatal(err)
	}
	if IsFile(tokenFile) {

		log.Printf("deleting %s\n", tokenFile)
		err := os.Remove(tokenFile)
		if err != nil {
			return Fatal(err)
		}
	} else {
		log.Printf("DeleteToken: %s is not a file\n", tokenFile)
	}
	return nil
}

func WriteToken(token *Token) error {

	log.Printf("writing token %s\n", token.Id)

	tokenFile, err := tokenFilename(token)
	if err != nil {
		return Fatal(err)
	}

	data, err := json.Marshal(token)
	if err != nil {
		return Fatal(err)
	}

	err = os.WriteFile(tokenFile, data, 0600)
	if err != nil {
		return Fatal(err)
	}
	return nil
}

func ReadToken(id string) (*Token, error) {
	tokenDir, err := tokenCacheDir()
	tokenFile := filepath.Join(tokenDir, id+".json")
	data, err := os.ReadFile(tokenFile)
	if err != nil {
		return nil, Fatal(err)
	}
	var token Token
	err = json.Unmarshal(data, &token)
	if err != nil {
		return nil, Fatal(err)
	}
	log.Printf("read token %s\n", token.Id)
	return &token, nil
}

func WriteTokenMap(tokens map[string]*Token) error {
	for _, token := range tokens {
		err := WriteToken(token)
		if err != nil {
			return Fatal(err)
		}
	}
	return nil
}

func ListTokenIds() ([]string, error) {
	tokenDir, err := tokenCacheDir()
	if err != nil {
		return nil, Fatal(err)
	}
	entries, err := os.ReadDir(tokenDir)
	if err != nil {
		return nil, Fatal(err)
	}
	ids := []string{}
	for _, entry := range entries {
		name := entry.Name()
		if entry.Type().IsRegular() && strings.HasSuffix(name, ".json") {
			id := strings.TrimSuffix(name, ".json")
			ids = append(ids, id)
		}
	}
	return ids, nil
}

func ReadTokenMap() (map[string]*Token, error) {
	ids, err := ListTokenIds()
	if err != nil {
		return nil, Fatal(err)
	}
	tokens := make(map[string]*Token)
	for _, id := range ids {
		token, err := ReadToken(id)
		if err != nil {
			return nil, Fatal(err)
		}
		tokens[id] = token
	}
	return tokens, nil
}
