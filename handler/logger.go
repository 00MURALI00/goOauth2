package handler

import (
	"log"
	"net/http"
)

func Logger(next http.Handler) http.Handler {

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		log.Println("----- REQUEST -----")
		log.Println("Method:", r.Method)
		log.Println("Path:", r.URL.Path)
		log.Println("Query:", r.URL.RawQuery)

		err := r.ParseForm()
		if err == nil && len(r.Form) > 0 {
			log.Println("Form:", r.Form)
		}

		next.ServeHTTP(w, r)

		log.Println("----- END REQUEST -----")
	})
}