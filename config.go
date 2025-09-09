package main

import (
	"fmt"
	"math/rand"
	"time"

	"github.com/spf13/viper"
)

// адреса серверов автоизации VK ID и публичный ключ для проверки JWT
const (
	AUTH_URL          = "https://id.vk.ru/authorize"
	VKID_API_URL      = "https://id.vk.ru/oauth2"
	VK_JWT_PUBLIC_KEY = `-----BEGIN PUBLIC KEY-----
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAvsvJlhFX9Ju/pvCz1frB
DgJs592VjdwQuRAmnlJAItyHkoiDIOEocPzgcUBTbDf1plDcTyO2RCkUt0pz0WK6
6HNhpJyIfARjaWHeUlv4TpuHXAJJsBKklkU2gf1cjID+40sWWYjtq5dAkXnSJUVA
UR+sq0lJ7GmTdJtAr8hzESqGEcSP15PTs7VUdHZ1nkC2XgkuR8KmKAUb388ji1Q4
n02rJNOPQgd9r0ac4N2v/yTAFPXumO78N25bpcuWf5vcL9e8THk/U2zt7wf+aAWL
748e0pREqNluTBJNZfmhC79Xx6GHtwqHyyduiqfPmejmiujNM/rqnA4e30Tg86Yn
cNZ6vLJyF72Eva1wXchukH/aLispbY+EqNPxxn4zzCWaLKHG87gaCxpVv9Tm0jSD
2es22NjrUbtb+2pAGnXbyDp2eGUqw0RrTQFZqt/VcmmSCE45FlcZMT28otrwG1ZB
kZAb5Js3wLEch3ZfYL8sjhyNRPBmJBrAvzrd8qa3rdUjkC9sKyjGAaHu2MNmFl1Y
JFQ3J54tGpkGgJjD7Kz3w0K6OiPDlVCNQN5sqXm24fCw85Pbi8SJiaLTp/CImrs1
Z3nHW5q8hljA7OGmqfOP0nZS/5zW9GHPyepsI1rW6CympYLJ15WeNzePxYS5KEX9
EncmkSD9b45ge95hJeJZteUCAwEAAQ==
-----END PUBLIC KEY-----`
)

// для генерации случайной строки state
const (
	randomCharset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-"
	minRandomLength = 32
)

// идентификаторы вашего приложения - получаем здесь https://id.vk.com/about/business/go
var (
	APP_ID,
	APP_SECRET string
)

// На этот адрес будет перенаправлен запрос после успешной автоизации в ВК.
// Ответ от сервера авторизации содержит code & device_ID, необходимые для дальнейшего обмена их на токены.
// По  этому адресу регистрируем соответсвующие обработчики.
var REDIRECT_URI string

// Переменные для инициализации генератора случайных чисел
var (
	seed   int64
	random *rand.Rand
)

func init() {
	viper.SetConfigName("config")
	viper.AddConfigPath(".")
	err := viper.ReadInConfig()
	if err != nil {
		panic(fmt.Errorf("fatal error config file: %w", err))
	}
	APP_ID = viper.GetString("APP_ID")
	APP_SECRET = viper.GetString("APP_SECRET")
	REDIRECT_URI = viper.GetString("REDIRECT_URI")

	seed = time.Now().UnixNano()
	random = rand.New(rand.NewSource(seed))
}
