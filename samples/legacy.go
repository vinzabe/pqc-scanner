package main

import (
    "crypto/rand"
    "crypto/rsa"
    "crypto/ecdsa"
    "crypto/elliptic"
)

func makeRSA() (*rsa.PrivateKey, error) {
    return rsa.GenerateKey(rand.Reader, 2048)
}

func makeEC() (*ecdsa.PrivateKey, error) {
    return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}
