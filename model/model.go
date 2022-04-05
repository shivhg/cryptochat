package model

import "gorm.io/gorm"

type Message struct {
	gorm.Model
	From      string
	To        string
	Text      string
	Delivered bool
}

type User struct {
	gorm.Model
	Address string
	Nonce string
}
