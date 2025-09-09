package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"strings"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/oauth2"
)

func GenerateRandomString(length int) string {
	if length < minRandomLength {
		length = minRandomLength
	}
	b := make([]byte, length)
	for i := range b {
		b[i] = randomCharset[random.Intn(len(randomCharset))]
	}
	return string(b)
}

func HashStringSHA256(input string) string {
	hasher := sha256.New()
	hasher.Write([]byte(input))
	return hex.EncodeToString(hasher.Sum(nil))
}

// наш хэндлер 
type VKIDHandler struct {
	conf oauth2.Config
	PKCE *PKCEData
	tmpl *template.Template
}

func NewVKIDHandler(scope string) *VKIDHandler {
	return &VKIDHandler{
		conf: oauth2.Config{
			ClientID:     APP_ID,
			ClientSecret: APP_SECRET,
			RedirectURL:  REDIRECT_URI,
			Scopes:       strings.Fields(scope),
			Endpoint: oauth2.Endpoint{
				AuthURL:  AUTH_URL,
				TokenURL: VKID_API_URL + "/auth",
			},
		},
		PKCE: NewPKCEData(),
		tmpl: NewTemplates(),
	}
}

// generateState() генерирует случайную строку state и схраняет её хэш в хэндлере
func (vk *VKIDHandler) generateState() string {
	state := GenerateRandomString(64)
	vk.PKCE.StateHash = HashStringSHA256(state)
	return state
}

// AuthPage вручную генерирует ссылку для авторизации через VKID и отображает её в браузере в виде кнопки.
// В ходе генерации к AUTH_URL "https://id.vk.com/authorize" добавляются query параметры:
//
//	"response_type"         "code"
//	"client_id"             APP_ID
//	"redirect_uri"          REDIRECT_URI
//	"code_challenge"        codeChallenge
//	"code_challenge_method" "S256"
//	"state"                 state
//	"scope"                 "email phone"
//
// После авторизации пользователь перенаправялется на REDIRECT_URI.
// Ответ от сервера авторизации содержит code & device_ID, необходимые для дальнейшего обмена их на токены.
func (vk *VKIDHandler) AuthPage(w http.ResponseWriter, r *http.Request) {
	url := makeAuthURL(vk.PKCE.CodeChallenge, vk.generateState(), strings.Join(vk.conf.Scopes, " "))
	//fmt.Println(url)
	err := vk.tmpl.ExecuteTemplate(w, "authButton.html", struct {
		URL string
	}{
		URL: url,
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

// AuthPageOA2 также генерирует ссылку для авторизации через VKID и отображает её в браузере в виде кнопки.
// В отличии от AuthPage генерация ссылки осуществляется при помощи функции AuthCodeURL пакета oauth2.
// После авторизации пользователь перенаправялется на REDIRECT_URI.
// Ответ от сервера авторизации содержит code & device_ID, необходимые для дальнейшего обмена их на токены.
func (vk *VKIDHandler) AuthPageOA2(w http.ResponseWriter, r *http.Request) {
	url := vk.conf.AuthCodeURL(vk.generateState(), oauth2.S256ChallengeOption(vk.PKCE.CodeVerifier))
	//fmt.Println(url)
	err := vk.tmpl.ExecuteTemplate(w, "authButton.html", struct {
		URL string
	}{
		URL: url,
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

// OneTap авторизует пользователя при помощи кнопки OneTap и VKIDSDK https://github.com/VKCOM/vkid-web-sdk
// После авторизации пользователь перенаправялется на REDIRECT_URI.
// Ответ от сервера авторизации содержит code & device_ID, необходимые для дальнейшего обмена их на токены.
func (vk *VKIDHandler) AuthPageOneTap(w http.ResponseWriter, r *http.Request) {
	err := vk.tmpl.ExecuteTemplate(w, "oneTap.html", struct {
		ClientID, RedirectURL, State, CodeChallenge, Scope string
	}{
		ClientID:      APP_ID,
		RedirectURL:   REDIRECT_URI,
		State:         vk.generateState(),
		CodeChallenge: vk.PKCE.CodeChallenge,
		Scope:         strings.Join(vk.conf.Scopes, " "),
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

// Callback обрабатывает ответ от сервера аутенфикации ВК после разрешения
// пользователя и обменивает полученные "code" "device_id" на токены доступа.
// После получения токенов можно начинать взаимодействие с API VK.
// В данном случае информации о пользователе и токене отображается в браузере.
func (vk *VKIDHandler) Callback(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	deviceID := r.URL.Query().Get("device_id")
	if code == "" {
		http.Error(w, "vk auth error, empty code returned.", http.StatusOK)
		return
	}
	if deviceID == "" {
		http.Error(w, "vk auth error, empty device_id returned", http.StatusOK)
		return
	}
	state := r.URL.Query().Get("state")
	if hash := HashStringSHA256(state); hash != vk.PKCE.StateHash {
		fmt.Fprintf(w,
			`Looks like your data is spoofing - another state. Try again with accurancy.
			initial state hash from backend - %v
			last state hash from AUTH VK server - %v`, vk.PKCE.StateHash, hash)
		return
	}
	accessData, err := getToken(code, deviceID, vk.PKCE.CodeVerifier, vk.generateState())
	if err != nil {
		http.Error(w, err.Error(), http.StatusOK)
		return
	}
	if hash := HashStringSHA256(accessData.State); hash != vk.PKCE.StateHash {
		fmt.Fprintf(w,
			`Looks like your data is spoofing - another state. Try again with accurancy.
			initial state hash from backend - %v
			last state hash from AUTH VK server - %v`, vk.PKCE.StateHash, hash)
		return
	}

	cl := &IDTokenClaims{}

	token, err := jwt.ParseWithClaims(accessData.IDToken, cl, func(t *jwt.Token) (any, error) {
		method, ok := t.Method.(*jwt.SigningMethodRSA)
		if !ok || method.Alg() != "RS256" {
			return nil, fmt.Errorf("bad sign method - %v", t.Header["alg"])
		}
		key, err := jwt.ParseRSAPublicKeyFromPEM([]byte(VK_JWT_PUBLIC_KEY))
		if err != nil {
			return nil, fmt.Errorf("ошибка парсинга публичного ключа: %w", err)
		}
		return key, nil
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		log.Println("cant parse jwt", err)
		return
	}
	if !token.Valid {
		http.Error(w, "invalid JWT", http.StatusInternalServerError)
		return
	}

	userInfo, err := getUserInfo(accessData.AccessToken)
	if err != nil {
		fmt.Fprintf(w, "request error: %v", err)
		return
	}
	err = vk.tmpl.ExecuteTemplate(w, "totalInfo.html", AccessAndUserInfo{
		AI: accessData,
		UI: userInfo,
		Cl: cl,
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		log.Println("cant render totalinfo template", err)
		return
	}
}

// CallbackOA2 также обрабатывает ответ от сервера аутенфикации ВК после разрешения пользователя
// но для получения токена используется метод Exchange библиотеки oauth2, а не ручной запрос
// На основании полученного токена создается http.Client для взаимодействия с API VK.
func (vk *VKIDHandler) CallbackOA2(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	deviceID := r.URL.Query().Get("device_id")
	if code == "" {
		http.Error(w, "vk auth error, empty code returned.", http.StatusOK)
		return
	}
	if deviceID == "" {
		http.Error(w, "vk auth error, empty device_id returned", http.StatusOK)
		return
	}
	state := r.URL.Query().Get("state")
	if hash := HashStringSHA256(state); hash != vk.PKCE.StateHash {
		fmt.Fprintf(w,
			`Looks like your data is spoofing - another state. Try again with accurancy.
			initial state hash from backend - %v
			last state hash from AUTH VK server - %v`, vk.PKCE.StateHash, hash)
		return
	}
	ctx := context.Background()
	tok, err := vk.conf.Exchange(ctx, code, oauth2.VerifierOption(vk.PKCE.CodeVerifier), oauth2.SetAuthURLParam("device_id", deviceID))
	if err != nil {
		http.Error(w, err.Error(), http.StatusOK)
		return
	}
	//fmt.Printf("%#v\n", tok)
	uid, _ := tok.Extra("user_id").(float64)
	idToken := tok.Extra("id_token").(string)
	scope := tok.Extra("scope").(string)

	// заполняем структуру &AccessVKInfo{} данными из токена
	accessData := &AccessVKInfo{
		AccessToken:  tok.AccessToken,
		RefreshToken: tok.RefreshToken,
		TokenType:    tok.TokenType,
		UserID:       int(uid),
		IDToken:      idToken,
		Scope:        scope,
	}

	// получаем данные о JWT ("id_token")
	cl := &IDTokenClaims{}
	token, err := jwt.ParseWithClaims(accessData.IDToken, cl, func(t *jwt.Token) (any, error) {
		method, ok := t.Method.(*jwt.SigningMethodRSA)
		if !ok || method.Alg() != "RS256" {
			return nil, fmt.Errorf("bad sign method - %v", t.Header["alg"])
		}
		key, err := jwt.ParseRSAPublicKeyFromPEM([]byte(VK_JWT_PUBLIC_KEY))
		if err != nil {
			return nil, fmt.Errorf("ошибка парсинга публичного ключа: %w", err)
		}
		return key, nil
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		log.Println("cant parse jwt", err)
		return
	}
	if !token.Valid {
		http.Error(w, "invalid JWT", http.StatusInternalServerError)
		return
	}

	client := vk.conf.Client(ctx, tok)

	userInfoURL := VKID_API_URL + "/user_info?&client_id=%v"
	resp, err := client.Get(fmt.Sprintf(userInfoURL, APP_ID))
	if err != nil {
		http.Error(w, err.Error(), http.StatusOK)
		return
	}
	userInfo := &UserInfo{}
	err = json.NewDecoder(resp.Body).Decode(userInfo)
	if err != nil {
		http.Error(w, err.Error(), http.StatusOK)
		return
	}
	err = vk.tmpl.ExecuteTemplate(w, "totalInfo.html", AccessAndUserInfo{
		AI: accessData,
		UI: userInfo,
		Cl: cl,
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusOK)
		return
	}
}
