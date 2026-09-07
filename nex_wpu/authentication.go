// Package nex_wpu implements the Wii Party U NEX auth/secure servers.
package nex_wpu

import (
	"fmt"
	"os"
	"strconv"

	nex "github.com/PretendoNetwork/nex-go/v2"
	"github.com/PretendoNetwork/nex-go/v2/constants"
	"github.com/PretendoNetwork/nex-go/v2/types"
	common_ticket_granting "github.com/PretendoNetwork/nex-protocols-common-go/v2/ticket-granting"
	ticket_granting "github.com/PretendoNetwork/nex-protocols-go/v2/ticket-granting"
	"github.com/Protarium-Network/wii-party-u-nex/globals"
)

// AccessKey was recovered by brute-forcing nex-go's PRUDPv1 SYN signature
// (HMAC-MD5) against a real CONNECT packet captured from the console -
// nexpy.rpx has no nex.rpl import and no plaintext access key string, so
// static analysis alone did not find it. See docs/access-key-recovery.md.
const AccessKey = "a5b77314"

var AuthenticationServer *nex.PRUDPServer
var AuthenticationEndpoint *nex.PRUDPEndPoint

func StartAuthenticationServer() {
	AuthenticationServer = nex.NewPRUDPServer()
	AuthenticationServer.LibraryVersions.SetDefault(nex.NewLibraryVersion(3, 0, 5))
	AuthenticationServer.AccessKey = AccessKey
	AuthenticationServer.PRUDPV1Settings.LegacyConnectionSignature = false

	AuthenticationEndpoint = nex.NewPRUDPEndPoint(1)
	AuthenticationEndpoint.ServerAccount = globals.AuthenticationServerAccount
	AuthenticationEndpoint.AccountDetailsByPID = globals.AccountDetailsByPID
	AuthenticationEndpoint.AccountDetailsByUsername = globals.AccountDetailsByUsername
	AuthenticationServer.BindPRUDPEndPoint(AuthenticationEndpoint)
	AuthenticationEndpoint.OnData(logPacket("Auth"))

	protocol := ticket_granting.NewProtocol()
	AuthenticationEndpoint.RegisterServiceProtocol(protocol)
	common := common_ticket_granting.NewCommonProtocol(protocol)

	securePort := envPort("PN_WPU_SECURE_PORT", 27001)
	secureURL := types.NewStationURL("")
	secureURL.SetURLType(constants.StationURLPRUDPS)
	secureURL.SetAddress(envString("PN_WPU_SECURE_HOST", "localhost"))
	secureURL.SetPortNumber(uint16(securePort))
	secureURL.SetConnectionID(1)
	secureURL.SetPrincipalID(types.NewPID(2))
	secureURL.SetStreamID(1)
	secureURL.SetStreamType(constants.StreamTypeRVSecure)
	secureURL.SetType(uint8(constants.StationURLFlagPublic))
	common.ValidateLoginData = globals.ValidateLoginData
	common.SecureStationURL = secureURL
	common.BuildName = types.NewString("")
	common.SecureServerAccount = globals.SecureServerAccount

	port := envPort("PN_WPU_AUTH_PORT", 27000)
	globals.Logger.Successf("[WPU] Authentication server listening on UDP %d", port)
	AuthenticationServer.Listen(port)
}

func logPacket(side string) func(nex.PacketInterface) {
	return func(packet nex.PacketInterface) {
		request := packet.RMCMessage()
		if request != nil {
			fmt.Printf("[WPU %s] PID=%d protocol=0x%02X method=0x%02X\n", side, uint64(packet.Sender().PID()), request.ProtocolID, request.MethodID)
		}
	}
}

func envPort(name string, fallback int) int {
	if parsed, err := strconv.Atoi(os.Getenv(name)); err == nil && parsed > 0 {
		return parsed
	}
	return fallback
}

func envString(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}
