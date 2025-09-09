package main

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"net/url"
)

// makeAuthURL генерирует ссылку для авторизации вручную путем добавления query
func makeAuthURL(codeChallenge, state, scope string) string {
	authURL, _ := url.Parse(AUTH_URL)
	q := url.Values{
		"response_type":         []string{"code"},
		"client_id":             []string{APP_ID},
		"redirect_uri":          []string{REDIRECT_URI},
		"code_challenge":        []string{codeChallenge},
		"code_challenge_method": []string{"S256"},
		"state":                 []string{state},
		"scope":                 []string{scope},
	}
	authURL.RawQuery = q.Encode()
	return authURL.String()
}

// getToken отправляет POST запрос на сервер аутенфикации ВК и сериализует тело ответа в
// в структуру AccessVKInfo, содержащую необходимые токены и др. информацию
func getToken(code, deviceID, codeVerifier, state string) (*AccessVKInfo, error) {
	toPost := url.Values{
		"grant_type":    []string{"authorization_code"},
		"code_verifier": []string{codeVerifier},
		"redirect_uri":  []string{REDIRECT_URI},
		"code":          []string{code},
		"device_id":     []string{deviceID},
		"state":         []string{state},
		"client_id":     []string{APP_ID},
	}
	resp, err := http.PostForm(VKID_API_URL+"/auth", toPost)
	if err != nil {
		log.Printf("cant post data on %v - %v\n", VKID_API_URL+"/auth", err)
		return nil, err
	}
	var td map[string]any
	err = json.NewDecoder(resp.Body).Decode(&td)
	if err != nil {
		log.Printf("cant unmarshal JSON from %v - %v\n", VKID_API_URL+"/auth", err)
		return nil, err
	}
	if _, ok := td["error"]; ok {
		log.Printf("cant get token from %v - %v\n", VKID_API_URL+"/auth", td["error_description"])
		return nil, errors.New(td["error_description"].(string))
	}

	buf, err := json.Marshal(td)
	if err != nil {
		log.Printf("cant marshal JSON from %v - %v\n", VKID_API_URL+"/auth", err)
		return nil, err
	}
	info := &AccessVKInfo{}
	err = json.Unmarshal(buf, info)
	if err != nil {
		log.Printf("cant unmarshal JSON from data - %v\n", err)
		return nil, err
	}
	return info, nil
}

// getUserInfo делает запрос POST https://id.vk.com/oauth2/user_info.
// Полученное тело ответа сериализуется в соответствующую структуру UserInfo
func getUserInfo(accessToken string) (*UserInfo, error) {
	uri := VKID_API_URL + "/user_info"
	toPost := url.Values{
		"client_id":    []string{APP_ID},
		"access_token": []string{accessToken},
	}
	resp, err := http.PostForm(uri, toPost)
	if err != nil {
		log.Printf("cant post data on %v - %v\n", uri, err)
		return nil, err
	}
	var v map[string]any
	err = json.NewDecoder(resp.Body).Decode(&v)
	if err != nil {
		log.Printf("cant unmarshal JSON from %v - %v\n", uri, err)
		return nil, err
	}
	if _, ok := v["error"]; ok {
		log.Printf("cant get info about user from %v - %v\n", uri, v["error_description"])
		return nil, errors.New(v["error_description"].(string))
	}

	buf, err := json.Marshal(v)
	if err != nil {
		log.Printf("cant marshal JSON from %v - %v\n", uri, err)
		return nil, err
	}
	info := &UserInfo{}
	err = json.Unmarshal(buf, info)
	if err != nil {
		log.Printf("cant unmarshal JSON from data - %v\n", err)
		return nil, err
	}
	return info, nil
}