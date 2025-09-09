package main

import (
	"html/template"
	"log"
)

func NewTemplates() *template.Template {
	tmpl, err := template.ParseGlob("./templates/*.html")
	if err != nil {
		log.Fatalf("Ошибка при парсинге файлов - %v\n", err)
	}
	return tmpl
}
