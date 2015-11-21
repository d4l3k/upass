package main

import (
	"crypto/rsa"
	"errors"
	"flag"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"time"

	"github.com/PuerkitoBio/goquery"
	"github.com/jinzhu/gorm"

	_ "github.com/mattn/go-sqlite3"
)

type User struct {
	Username, Password, University string
	LastActivated                  time.Time
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

func (u *User) Activate() error {
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
	//body, _ := ioutil.ReadAll(resp.Body)
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

	doc3, err := goquery.NewDocumentFromResponse(resp4)
	if err != nil {
		return err
	}
	if doc3.Find("#form-request").Length() == 0 {
		return errors.New("Invalid username or password details.")
	}

	action = "https://upassbc.translink.ca" + doc3.Find("#form-request").AttrOr("action", "")
	vals := url.Values{"requestButton": {"Request"}}
	checkboxes := doc3.Find("#form-request input:nth-child(1)[type=\"checkbox\"]")
	log.Printf("Activating UPass %s, count %d", u.Username, checkboxes.Length())
	if checkboxes.Length() == 0 {
		return nil
	}
	doc3.Find("#form-request input").Each(func(i int, sel *goquery.Selection) {
		name := sel.AttrOr("name", "")
		val := sel.AttrOr("value", "")
		if len(name) == 0 || len(val) == 0 {
			return
		}
		vals[name] = append(vals[name], val)
	})
	boxName := checkboxes.Last().AttrOr("name", "")
	vals[boxName] = append(vals[boxName], "true")

	log.Println("vals", vals)
	resp5, err := c.PostForm(action, vals)
	if err != nil {
		return err
	}
	defer resp5.Body.Close()
	body, _ := ioutil.ReadAll(resp5.Body)
	log.Println(string(body))

	u.LastActivated = time.Now()

	return nil
}

func activateEverything(db gorm.DB, key *rsa.PrivateKey) {
	log.Println("Checking for new UPasses...")
	var users []*User
	db.Find(&users)
	for i, user := range users {
		if err := user.Decrypt(key); err != nil {
			log.Printf("ERR decrypting %s, %s", user.Username, err)
			continue
		}
		if err := user.Activate(); err != nil {
			log.Printf("ERR activating %s, %s", user.Username, err)
			continue
		}
		if err := user.Decrypt(key); err != nil {
			log.Printf("ERR decrypting %s, %s", user.Username, err)
			continue
		}
		db.Model(user).Update("last_activated", user.LastActivated)
		// Remove decrypted version from memory.
		users[i] = nil
	}
}

func pollActivator(db gorm.DB, key *rsa.PrivateKey) {
	ticker := time.NewTicker(24 * time.Hour)
	for _ = range ticker.C {
		activateEverything(db, key)
	}
}

var addr = flag.String("addr", ":3000", "The address to listen on.")

func main() {
	flag.Parse()

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

	go pollActivator(db, key)
	go activateEverything(db, key)

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
		if err := user.Encrypt(key); err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		if err := db.Create(user).Error; err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		w.Write([]byte("Successfully created renewer."))
	})
	log.Printf("Listening on %s", *addr)
	log.Fatal(http.ListenAndServe(*addr, nil))
}
