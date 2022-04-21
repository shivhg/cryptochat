package service

import (
	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/p2p-chat/model"
	"gorm.io/gorm"
)

type BlockChainAuthenticator struct {
	Db *gorm.DB
}

func (b BlockChainAuthenticator) Authenticate(walletAddress string, signature string) bool {
	var user model.User
	tx := b.Db.Find(&user, model.User{Address: walletAddress})
	if tx.Error != nil {
		return false
	}
	verified := verifySig(walletAddress, signature, []byte("I am signing my one-time nonce: "+user.Nonce))

	return verified
}

func verifySig(from, sigHex string, msg []byte) bool {
	sig := hexutil.MustDecode(sigHex)
	msg = accounts.TextHash(msg)
	sig[crypto.RecoveryIDOffset] -= 27 // Transform yellow paper V from 27/28 to 0/1
	recovered, err := crypto.SigToPub(msg, sig)
	if err != nil {
		return false
	}
	recoveredAddr := crypto.PubkeyToAddress(*recovered)
	return from == recoveredAddr.Hex()
}
