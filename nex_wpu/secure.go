package nex_wpu

import (
	"fmt"
	"sync"
	"time"

	nex "github.com/PretendoNetwork/nex-go/v2"
	"github.com/PretendoNetwork/nex-go/v2/types"
	common_nat "github.com/PretendoNetwork/nex-protocols-common-go/v2/nat-traversal"
	common_secure "github.com/PretendoNetwork/nex-protocols-common-go/v2/secure-connection"
	common_utility "github.com/PretendoNetwork/nex-protocols-common-go/v2/utility"
	datastore "github.com/PretendoNetwork/nex-protocols-go/v2/datastore"
	datastoretypes "github.com/PretendoNetwork/nex-protocols-go/v2/datastore/types"
	nat "github.com/PretendoNetwork/nex-protocols-go/v2/nat-traversal"
	secure "github.com/PretendoNetwork/nex-protocols-go/v2/secure-connection"
	utility "github.com/PretendoNetwork/nex-protocols-go/v2/utility"
	"github.com/Protarium-Network/wii-party-u-nex/globals"
)

var SecureServer *nex.PRUDPServer
var SecureEndpoint *nex.PRUDPEndPoint

// ratingKey identifies one rating slot on one placeholder DataID. There's no
// database backing this yet - it's in-memory only, so it resets on restart -
// but it closes the loop enough to see a submitted rating reflected back.
type ratingKey struct {
	dataID uint64
	slot   uint8
}
type ratingState struct {
	totalValue int64
	count      uint32
}

var (
	ratingsMu    sync.Mutex
	ratingsStore = map[ratingKey]*ratingState{}
)

func StartSecureServer() {
	SecureServer = nex.NewPRUDPServer()
	SecureServer.LibraryVersions.SetDefault(nex.NewLibraryVersion(3, 0, 5))
	SecureServer.AccessKey = AccessKey
	SecureServer.PRUDPV1Settings.LegacyConnectionSignature = false

	SecureEndpoint = nex.NewPRUDPEndPoint(1)
	SecureEndpoint.IsSecureEndPoint = true
	SecureEndpoint.ServerAccount = globals.SecureServerAccount
	SecureEndpoint.AccountDetailsByPID = globals.AccountDetailsByPID
	SecureEndpoint.AccountDetailsByUsername = globals.AccountDetailsByUsername
	SecureServer.BindPRUDPEndPoint(SecureEndpoint)
	SecureEndpoint.OnData(logPacket("Secure"))
	SecureEndpoint.OnConnectionEnded(func(c *nex.PRUDPConnection) {
		fmt.Printf("[WPU Secure] PID=%d disconnected\n", uint64(c.PID()))
	})

	registerSecureProtocols()

	port := envPort("PN_WPU_SECURE_PORT", 27001)
	globals.Logger.Successf("[WPU] Secure server listening on UDP %d", port)
	SecureServer.Listen(port)
}

func registerSecureProtocols() {
	secureProtocol := secure.NewProtocol()
	SecureEndpoint.RegisterServiceProtocol(secureProtocol)
	secureCommon := common_secure.NewCommonProtocol(secureProtocol)
	secureCommon.EnableInsecureRegister()
	// Telemetry only - no shared DB for this service yet.
	secureCommon.CreateReportDBRecord = func(types.PID, types.UInt32, types.QBuffer) error { return nil }

	utilityProtocol := utility.NewProtocol()
	SecureEndpoint.RegisterServiceProtocol(utilityProtocol)
	common_utility.NewCommonProtocol(utilityProtocol)

	natProtocol := nat.NewProtocol()
	SecureEndpoint.RegisterServiceProtocol(natProtocol)
	common_nat.NewCommonProtocol(natProtocol)

	// The Notes tab bootstraps by querying DataStore (nmg/npg/mira tags - see
	// docs/datastore-tags.md). Leaving the protocol unregistered makes the
	// retail client wait forever since no RMC response is ever emitted for
	// SearchObject; start with an empty-but-successful bootstrap result
	// (mirrors the same fix MH3U needed) and fill in real tag data once we
	// see what the client actually searches for.
	dataStoreProtocol := datastore.NewProtocol()
	SecureEndpoint.RegisterServiceProtocol(dataStoreProtocol)
	dataStoreProtocol.SetHandlerSearchObject(searchDataStoreObjects)
	dataStoreProtocol.SetHandlerGetRatings(getDataStoreRatings)
	dataStoreProtocol.SetHandlerRateObject(rateDataStoreObject)
}

func searchDataStoreObjects(_ error, packet nex.PacketInterface, callID uint32, param datastoretypes.DataStoreSearchParam) (*nex.RMCMessage, *nex.Error) {
	tags := make([]string, len(param.Tags))
	for i, t := range param.Tags {
		tags[i] = string(t)
	}
	owners := make([]uint64, len(param.OwnerIDs))
	for i, o := range param.OwnerIDs {
		owners[i] = uint64(o)
	}
	dataTypes := make([]uint16, len(param.DataTypes))
	for i, d := range param.DataTypes {
		dataTypes[i] = uint16(d)
	}
	fmt.Printf("[WPU DataStore] SearchObject searchTarget=%d ownerType=%d owners=%v dataType=%d dataTypes=%v tags=%v resultOrderColumn=%d resultOrder=%d resultRange=%+v resultOption=%d minRatingFreq=%d useCache=%v totalCountEnabled=%v referDataID=%d\n",
		uint8(param.SearchTarget), uint8(param.OwnerType), owners, uint16(param.DataType), dataTypes, tags,
		uint8(param.ResultOrderColumn), uint8(param.ResultOrder), param.ResultRange, uint8(param.ResultOption),
		uint32(param.MinimalRatingFrequency), bool(param.UseCache), bool(param.TotalCountEnabled), uint32(param.ReferDataID))

	endpoint := packet.Sender().Endpoint()
	result := datastoretypes.NewDataStoreSearchResult()
	result.Result = types.NewList[datastoretypes.DataStoreMetaInfo]()

	// EXPERIMENT: a genuinely empty result (TotalCount=0) makes the client
	// bounce straight back out of the Notes screen instead of rendering it -
	// even though that's the same "empty but successful" shape MH3U's client
	// accepts fine. Try returning one placeholder slot (owned by the caller,
	// tagged with whatever tag they searched for) to see whether the client
	// just needs *an* object to exist before it will draw the screen.
	meta := datastoretypes.NewDataStoreMetaInfo()
	meta.DataID = types.NewUInt64(1)
	meta.OwnerID = packet.Sender().PID()
	meta.Size = types.NewUInt32(0)
	meta.Name = types.NewString("")
	meta.DataType = param.DataType
	meta.MetaBinary = types.NewQBuffer(nil)
	meta.Permission = datastoretypes.NewDataStorePermission()
	meta.Permission.Permission = types.NewUInt8(0)
	meta.Permission.RecipientIDs = types.NewList[types.PID]()
	meta.DelPermission = datastoretypes.NewDataStorePermission()
	meta.DelPermission.Permission = types.NewUInt8(0)
	meta.DelPermission.RecipientIDs = types.NewList[types.PID]()
	now := types.DateTime(0).Now()
	meta.CreatedTime = now
	meta.UpdatedTime = now
	meta.ReferredTime = now
	expire := types.NewDateTime(0)
	meta.ExpireTime = expire.FromTimestamp(time.Date(2099, 1, 1, 0, 0, 0, 0, time.UTC))
	meta.Period = types.NewUInt16(0)
	meta.Status = types.NewUInt8(0)
	meta.ReferredCnt = types.NewUInt32(0)
	meta.ReferDataID = types.NewUInt32(0)
	meta.Flag = types.NewUInt32(0)
	meta.Tags = types.NewList[types.String]()
	for _, t := range param.Tags {
		meta.Tags = append(meta.Tags, t)
	}
	meta.Ratings = types.NewList[datastoretypes.DataStoreRatingInfoWithSlot]()
	result.Result = append(result.Result, meta)
	result.TotalCount = types.NewUInt32(1)
	result.TotalCountType = types.NewUInt8(0)

	out := nex.NewByteStreamOut(endpoint.LibraryVersions(), endpoint.ByteStreamSettings())
	result.WriteTo(out)

	response := nex.NewRMCSuccess(endpoint, out.Bytes())
	response.ProtocolID = datastore.ProtocolID
	response.MethodID = datastore.MethodSearchObject
	response.CallID = callID
	return response, nil
}

// getDataStoreRatings answers with "unrated" (zero votes) for every
// requested DataID - the client asks for this right after SearchObject
// finds our placeholder object.
func getDataStoreRatings(_ error, packet nex.PacketInterface, callID uint32, dataIDs types.List[types.UInt64], _ types.UInt64) (*nex.RMCMessage, *nex.Error) {
	ids := make([]uint64, len(dataIDs))
	for i, id := range dataIDs {
		ids[i] = uint64(id)
	}
	fmt.Printf("[WPU DataStore] GetRatings dataIDs=%v\n", ids)

	endpoint := packet.Sender().Endpoint()
	ratings := types.NewList[datastoretypes.DataStoreRatingInfo]()
	ratingsMu.Lock()
	for _, id := range dataIDs {
		state := ratingsStore[ratingKey{dataID: uint64(id), slot: 0}]
		info := datastoretypes.NewDataStoreRatingInfo()
		if state != nil {
			info.TotalValue = types.NewInt64(state.totalValue)
			info.Count = types.NewUInt32(state.count)
		} else {
			info.TotalValue = types.NewInt64(0)
			info.Count = types.NewUInt32(0)
		}
		info.InitialValue = types.NewInt64(0)
		ratings = append(ratings, info)
	}
	ratingsMu.Unlock()

	out := nex.NewByteStreamOut(endpoint.LibraryVersions(), endpoint.ByteStreamSettings())
	ratings.WriteTo(out)

	response := nex.NewRMCSuccess(endpoint, out.Bytes())
	response.ProtocolID = datastore.ProtocolID
	response.MethodID = datastore.MethodGetRatings
	response.CallID = callID
	return response, nil
}

// rateDataStoreObject records a submitted rating in the in-memory store
// (see ratingsStore - no database yet) and, if the client asked for it,
// echoes back the updated aggregate.
func rateDataStoreObject(_ error, packet nex.PacketInterface, callID uint32, target datastoretypes.DataStoreRatingTarget, param datastoretypes.DataStoreRateObjectParam, fetchRatings types.Bool) (*nex.RMCMessage, *nex.Error) {
	key := ratingKey{dataID: uint64(target.DataID), slot: uint8(target.Slot)}

	ratingsMu.Lock()
	state := ratingsStore[key]
	if state == nil {
		state = &ratingState{}
		ratingsStore[key] = state
	}
	state.totalValue += int64(param.RatingValue)
	state.count++
	totalValue, count := state.totalValue, state.count
	ratingsMu.Unlock()

	fmt.Printf("[WPU DataStore] RateObject dataID=%d slot=%d value=%d fetchRatings=%v -> total=%d count=%d\n",
		uint64(target.DataID), uint8(target.Slot), int32(param.RatingValue), bool(fetchRatings), totalValue, count)

	endpoint := packet.Sender().Endpoint()
	out := nex.NewByteStreamOut(endpoint.LibraryVersions(), endpoint.ByteStreamSettings())
	if bool(fetchRatings) {
		info := datastoretypes.NewDataStoreRatingInfo()
		info.TotalValue = types.NewInt64(totalValue)
		info.Count = types.NewUInt32(count)
		info.InitialValue = types.NewInt64(0)
		info.WriteTo(out)
	}

	response := nex.NewRMCSuccess(endpoint, out.Bytes())
	response.ProtocolID = datastore.ProtocolID
	response.MethodID = datastore.MethodRateObject
	response.CallID = callID
	return response, nil
}
