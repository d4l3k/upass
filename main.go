package main

import (
	"errors"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"

	"github.com/PuerkitoBio/goquery"
	"github.com/jinzhu/gorm"

	_ "github.com/mattn/go-sqlite3"
)

type User struct {
	Username, Password, University string
	Encrypted                      bool
}

func (u User) Validate() error {
	if u.University != "ubc" {
		return errors.New("Only UBC is currently supported.")
	}
	if len(u.Username) == 0 {
		return errors.New("Invalid username.")
	}
	if len(u.Password) == 0 {
		return errors.New("Invalid password.")
	}
	return nil
}

func (u User) Activate() error {
	jar, err := cookiejar.New(nil)
	if err != nil {
		return err
	}
	c := &http.Client{
		Jar: jar,
	}
	resp, err := c.PostForm("https://upassbc.translink.ca/", url.Values{"PsiId": {u.University}})
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, _ := ioutil.ReadAll(resp.Body)
	//log.Println(string(body))

	// Log into shibboleth
	resp2, err := c.PostForm("https://shibboleth2.id.ubc.ca/idp/Authn/UserPassword", url.Values{
		"j_username": {u.Username},
		"j_password": {u.Password},
		"action":     {"Continue"},
	})
	if err != nil {
		return err
	}
	defer resp2.Body.Close()

	// Continue SAML
	doc, err := goquery.NewDocumentFromResponse(resp2)
	if err != nil {
		return err
	}
	action := doc.Find("form").AttrOr("action", "")
	relayState := doc.Find("input[name=\"RelayState\"]").AttrOr("value", "")
	samlResponse := doc.Find("input[name=\"SAMLResponse\"]").AttrOr("value", "")

	resp3, err := c.PostForm(action, url.Values{
		"RelayState":   {relayState},
		"SAMLResponse": {samlResponse},
		"action":       {"Continue"},
	})
	if err != nil {
		return err
	}
	defer resp3.Body.Close()

	// Continue upassbc login
	doc2, err := goquery.NewDocumentFromResponse(resp3)
	if err != nil {
		return err
	}
	action = doc2.Find("form").AttrOr("action", "")
	wa := doc2.Find("input[name=\"wa\"]").AttrOr("value", "")
	wresult := doc2.Find("input[name=\"wresult\"]").AttrOr("value", "")

	resp4, err := c.PostForm(action, url.Values{
		"wa":      {wa},
		"wresult": {wresult},
		"action":  {"Submit"},
	})
	if err != nil {
		return err
	}
	defer resp4.Body.Close()
	body, _ = ioutil.ReadAll(resp4.Body)
	log.Println(string(body))
	if !strings.Contains(string(body), "To request your U-Pass BC select the month and click") {
		return errors.New("Invalid username or password details.")
	}

	return nil
}

func main() {
	db, err := gorm.Open("sqlite3", "./user.db")
	if err != nil {
		log.Fatal(err)
	}
	db.CreateTable(&User{})
	db.AutoMigrate(&User{})

	key, err := readKeyOrGenerate("./db.key")
	if err != nil {
		log.Fatal(err)
	}

	http.Handle("/", http.FileServer(http.Dir("./static")))
	http.HandleFunc("/api/v1/register", func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		user := &User{
			University: r.FormValue("university"),
			Username:   r.FormValue("username"),
			Password:   r.FormValue("password"),
		}
		if err := user.Validate(); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		if err := user.Activate(); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		user.Encrypt(key)
		if err := db.Create(user).Error; err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		w.Write([]byte("Successfully created renewer."))
	})
	log.Println("Listening on :3000")
	log.Fatal(http.ListenAndServe(":3000", nil))
}
