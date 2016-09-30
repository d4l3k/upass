package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
)

const (
	blockType    = "RSA PRIVATE KEY"
	cipherType   = x509.PEMCipherAES256
	rsaBitLength = 4096
)

func readKeyOrGenerate(path, pass string) (*rsa.PrivateKey, error) {
	file, err := ioutil.ReadFile(path)
	var key *rsa.PrivateKey
	if err != nil {
		log.Printf("Generating new key %s...", path)
		key, err = rsa.GenerateKey(rand.Reader, rsaBitLength)
		if err != nil {
			return nil, err
		}
		raw := x509.MarshalPKCS1PrivateKey(key)
		block, err := x509.EncryptPEMBlock(rand.Reader, blockType, raw, []byte(pass), cipherType)
		if err != nil {
			return nil, err
		}
		encoded := pem.EncodeToMemory(block)
		ioutil.WriteFile(path, encoded, 0400)
	} else {
		log.Printf("Loading key %s...", path)
		block, _ := pem.Decode(file)
		if block == nil {
			return nil, fmt.Errorf("%s doesn't contain a PEM key", path)
		}
		raw, err := x509.DecryptPEMBlock(block, []byte(pass))
		if err != nil {
			return nil, err
		}
		key, err = x509.ParsePKCS1PrivateKey(raw)
		if err != nil {
			return nil, err
		}
	}
	return key, nil
}

func (u *User) Encrypt(key *rsa.PrivateKey) error {
	if u.Encrypted {
		return nil
	}
	encrypted, err := rsa.EncryptPKCS1v15(rand.Reader, &key.PublicKey, []byte(u.Password))
	if err != nil {
		return err
	}
	u.Password = string(encrypted)
	u.Encrypted = true
	return nil
}

func (u *User) Decrypt(key *rsa.PrivateKey) error {
	if !u.Encrypted {
		return nil
	}
	decrypted, err := rsa.DecryptPKCS1v15(rand.Reader, key, []byte(u.Password))
	if err != nil {
		return err
	}
	u.Password = string(decrypted)
	u.Encrypted = false
	return nil
}
