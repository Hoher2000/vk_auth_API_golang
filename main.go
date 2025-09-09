package main

import (
	"fmt"
	"log"
	"net/http"
)

func main() {
	h := NewVKIDHandler("email phone") // передаем scope
	//http.HandleFunc("/", h.AuthPage) // формируем ссылку для авторизации вручную
	//http.HandleFunc("/", h.AuthPageOA2) // формируем ссылку для авторизации при помощи библиотеки "golang.org/x/oauth2"
	http.HandleFunc("/", h.AuthPageOneTap) // используем виджет OneTap и фронтенд VKID SDK
	//http.HandleFunc("/callback", h.Callback) // получаем токен и данные о пользователе вручную
	http.HandleFunc("/callback", h.CallbackOA2) // получаем токен и данные о пользователе при помощи библиотеки "golang.org/x/oauth2"
	fmt.Println("Server is started on port 8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
