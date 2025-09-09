package main

import (
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/oauth2"
)

// PKCEData хранит коды "Proof Key for Code Exchange by OAuth Public Clients"
// и state - строка состояния в виде случайного набора символов: a-z, A-Z, 0-9, _, -, длиной не менее 32 символа.
// state необходим для защиты от подмены. Не храним state явно, храним его хэш.
type PKCEData struct {
	CodeVerifier  string
	CodeChallenge string
	StateHash     string
}

// NewPKCEData() создает ссылку на новый экземпляр PKCEData().
// CodeVerifier и CodeChallenge генерируются методами билиотеки oauth2
func NewPKCEData() *PKCEData {
	codeVerifier := oauth2.GenerateVerifier()
	return &PKCEData{
		CodeVerifier:  codeVerifier,
		CodeChallenge: oauth2.S256ChallengeFromVerifier(codeVerifier),
	}
}

// AccessVKInfo хранит информацию о токенах, полученных с сервера аутенфикации ВК
// Информация здесь https://id.vk.com/about/business/go/docs/ru/vkid/latest/vk-id/connection/tokens/about
type AccessVKInfo struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	UserID       int    `json:"user_id"`
	IDToken      string `json:"id_token"`
	Scope        string `json:"scope"`
	State        string `json:"state"`
}

// UserInfo хранит основную информацию о пользователе, полученную с сервера аутенфикации ВК после запроса POST https://id.vk.com/oauth2/user_info
// Информация здесь https://id.vk.com/about/business/go/docs/ru/vkid/latest/vk-id/connection/api-description.
// Для полученя другой информации о пользователе смотрите здесь https://dev.vk.com/ru/reference
type UserInfo struct {
	User struct {
		UserID    string `json:"user_id"`
		FirstName string `json:"first_name"`
		LastName  string `json:"last_name"`
		Phone     string `json:"phone"`
		Avatar    string `json:"avatar"`
		Email     string `json:"email"`
		Sex       int    `json:"sex"`
		Verified  bool   `json:"verified"`
		Birthday  string `json:"birthday"`
	} `json:"user"`
}

// IDTokenClaims это структура для сериализации id_token (JWT)
type IDTokenClaims struct {
	IIS                  string `json:"iss"` // "iss": "VK" - хост выдавший токен
	Sub                  int    `json:"sub"` // "sub": 00000000 - ID пользователя ВК
	App                  int    `json:"app"` // "app": 51812311 - идентификатор приложения
	Jti                  int    `json:"jti"` // "jti": 21 - тип токена (всегда 21)
	jwt.RegisteredClaims        // Включаем стандартные поля JWT
}

// Комплексная структура для рендеринга общего шаблона
type AccessAndUserInfo struct {
	AI *AccessVKInfo
	UI *UserInfo
	Cl *IDTokenClaims
}
