package main

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"
)

func TestUserEncryption(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 256)
	if err != nil {
		t.Fatal(err)
	}
	password := "testtest"
	user := &User{
		Username:   "testuser",
		Password:   password,
		University: "ubc",
	}
	if err := user.Encrypt(key); err != nil {
		t.Error(err)
	}
	if !user.Encrypted || user.Password == password {
		t.Errorf("failed to encrypt user %+v", user)
	}
	if err := user.Decrypt(key); err != nil {
		t.Error(err)
	}
	if user.Encrypted || user.Password != password {
		t.Errorf("failed to encrypt user %+v", user)
	}
}
