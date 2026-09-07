// Package globals holds process-wide state shared between the Wii Party U
// NEX auth/secure servers.
package globals

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"strconv"

	"github.com/PretendoNetwork/nex-go/v2"
	"github.com/PretendoNetwork/nex-go/v2/types"
	common_globals "github.com/PretendoNetwork/nex-protocols-common-go/v2/globals"
	"github.com/PretendoNetwork/plogger-go"
)

var (
	Logger *plogger.Logger

	KerberosPassword            = "password"
	AuthenticationServerAccount *nex.Account
	SecureServerAccount         *nex.Account

	// Must match PN_WPU_NEX_TOKEN_AES_KEY / PN_WPU_NEX_PASSWORD_SECRET on the
	// wpu-token account issuer - these two processes have to agree on both
	// secrets to decrypt/derive the same token and kerberos password.
	NEXTokenAESKey    []byte
	NEXPasswordSecret []byte
)

func InitAccounts() {
	AuthenticationServerAccount = nex.NewAccount(types.NewPID(1), "Quazal Authentication", KerberosPassword)
	SecureServerAccount = nex.NewAccount(types.NewPID(2), "Quazal Rendez-Vous", KerberosPassword)
}

func PasswordFromPID(pid types.PID) (string, uint32) {
	if len(NEXPasswordSecret) < 32 {
		return "", 1
	}
	pidBytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(pidBytes, uint64(pid))
	mac := hmac.New(sha256.New, NEXPasswordSecret)
	_, _ = mac.Write(pidBytes)
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil)), 0
}

func AccountDetailsByPID(pid types.PID) (*nex.Account, *nex.Error) {
	if pid.Equals(AuthenticationServerAccount.PID) {
		return AuthenticationServerAccount, nil
	}
	if pid.Equals(SecureServerAccount.PID) {
		return SecureServerAccount, nil
	}
	password, errorCode := PasswordFromPID(pid)
	if errorCode != 0 {
		return nil, nex.NewError(errorCode, "Failed to get password from PID")
	}
	return nex.NewAccount(pid, strconv.Itoa(int(pid)), password), nil
}

func AccountDetailsByUsername(username string) (*nex.Account, *nex.Error) {
	if username == AuthenticationServerAccount.Username {
		return AuthenticationServerAccount, nil
	}
	if username == SecureServerAccount.Username {
		return SecureServerAccount, nil
	}
	pidInt, err := strconv.Atoi(username)
	if err != nil {
		return nil, nex.NewError(nex.ResultCodes.RendezVous.InvalidUsername, "Invalid username")
	}
	pid := types.NewPID(uint64(pidInt))
	password, errorCode := PasswordFromPID(pid)
	if errorCode != 0 {
		return nil, nex.NewError(errorCode, "Failed to get password from PID")
	}
	return nex.NewAccount(pid, username, password), nil
}

func ValidateLoginData(pid types.PID, loginData types.DataHolder) *nex.Error {
	return common_globals.ValidatePretendoLoginData(pid, loginData, NEXTokenAESKey)
}
