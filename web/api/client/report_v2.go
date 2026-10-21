package client

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"errors"
	logger "github.com/komari-monitor/komari/utils/log"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
	"github.com/komari-monitor/komari/database/clients"
	"github.com/komari-monitor/komari/database/tasks"
	v2 "github.com/komari-monitor/komari/protocol/v2"
	"github.com/komari-monitor/komari/utils/notifier"
	agent_runtime "github.com/komari-monitor/komari/web/agent"
	"github.com/komari-monitor/komari/web/api"
	"github.com/komari-monitor/komari/web/connection"
	"github.com/komari-monitor/komari/web/filemanager"
)

const (
	// maxAgentCompressedBody caps the bytes an agent may put on the wire
	// (before gzip decoding) for the v2 JSON-RPC POST endpoint.
	maxAgentCompressedBody = 8 << 20
	// maxAgentDecompressedBody caps the bytes after gzip decoding, so a small
	// compressed payload cannot expand into a process-killing buffer.
	maxAgentDecompressedBody = 32 << 20
	// maxAgentWSMessage caps one inbound WebSocket message. gorilla/websocket
	// counts decompressed bytes against SetReadLimit.
	maxAgentWSMessage = 8 << 20
)

// errAgentBodyTooLarge is returned when a body fits the compressed limit but
// expands past the decompressed limit.
var errAgentBodyTooLarge = errors.New("agent request body exceeds decompressed size limit")

func readMaybeCompressedBody(w http.ResponseWriter, r *http.Request) ([]byte, error) {
	return readBodyWithLimits(w, r, maxAgentCompressedBody, maxAgentDecompressedBody)
}

// readBodyWithLimits reads an optionally gzip-encoded request body while
// enforcing both a compressed (wire) and a decompressed size cap. The limits
// are parameters so tests can exercise each branch without multi-megabyte
// input; production callers go through readMaybeCompressedBody.
func readBodyWithLimits(w http.ResponseWriter, r *http.Request, maxCompressed, maxDecompressed int64) ([]byte, error) {
	defer r.Body.Close()
	body := http.MaxBytesReader(w, r.Body, maxCompressed)
	var src io.Reader = body
	if strings.EqualFold(r.Header.Get("Content-Encoding"), "gzip") {
		zr, err := gzip.NewReader(body)
		if err != nil {
			return nil, err
		}
		defer zr.Close()
		src = zr
	}
	data, err := io.ReadAll(io.LimitReader(src, maxDecompressed+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maxDecompressed {
		return nil, errAgentBodyTooLarge
	}
	return data, nil
}

// bodyReadErrorStatus maps a body-read failure to the HTTP status the agent
// should see: anything that tripped a size limit is 413, other decode errors
// stay at 400.
func bodyReadErrorStatus(err error) int {
	var maxBytesErr *http.MaxBytesError
	if errors.As(err, &maxBytesErr) || errors.Is(err, errAgentBodyTooLarge) {
		return http.StatusRequestEntityTooLarge
	}
	return http.StatusBadRequest
}

func bindV2Params[T any](raw any, target *T) error {
	b, err := json.Marshal(raw)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, target)
}

func handleV2RPC(uuid string, req v2.Request, allowWait bool) v2.Response {
	if req.JSONRPC != v2.Version {
		return v2.Error(req.ID, -32600, "invalid jsonrpc version", nil)
	}
	switch req.Method {
	case v2.MethodAgentReport:
		var params v2.ReportParams
		if err := bindV2Params(req.Params, &params); err != nil {
			return v2.Error(req.ID, -32602, "invalid report params", err.Error())
		}
		if err := ingestReport(uuid, params.Report, true); err != nil {
			return v2.Error(req.ID, -32000, "failed to save report", err.Error())
		}
		return v2.Success(req.ID, gin.H{
			"status": "success",
			"events": agent_runtime.TakeV2Events(uuid, params.AckEventIDs, 8),
		})
	case v2.MethodAgentBasicInfo:
		var params v2.BasicInfoParams
		if err := bindV2Params(req.Params, &params); err != nil {
			return v2.Error(req.ID, -32602, "invalid basic info params", err.Error())
		}
		if err := ingestBasicInfo(uuid, params.Info, ""); err != nil {
			return v2.Error(req.ID, -32000, "failed to save basic info", err.Error())
		}
		return v2.Success(req.ID, gin.H{"status": "success"})
	case v2.MethodAgentPingResult:
		var params v2.PingResultParams
		if err := bindV2Params(req.Params, &params); err != nil {
			return v2.Error(req.ID, -32602, "invalid ping result params", err.Error())
		}
		if err := ingestPingResult(uuid, params.TaskID, params.Value); err != nil {
			return v2.Error(req.ID, -32000, "failed to save ping result", err.Error())
		}
		return v2.Success(req.ID, gin.H{"status": "success"})
	case v2.MethodAgentTaskResult:
		var params v2.TaskResultParams
		if err := bindV2Params(req.Params, &params); err != nil {
			return v2.Error(req.ID, -32602, "invalid task result params", err.Error())
		}
		finishedAt := params.FinishedAt
		if finishedAt.IsZero() {
			finishedAt = time.Now().UTC()
		}
		if err := tasks.SaveTaskResult(params.TaskID, uuid, params.Result, params.ExitCode, finishedAt); err != nil {
			return v2.Error(req.ID, -32000, "failed to save task result", err.Error())
		}
		return v2.Success(req.ID, gin.H{"status": "success"})
	case v2.MethodAgentPull:
		var params v2.PullParams
		if err := bindV2Params(req.Params, &params); err != nil {
			return v2.Error(req.ID, -32602, "invalid pull params", err.Error())
		}
		refreshPostPresence(uuid)
		agent_runtime.MarkV2Client(uuid)
		timeout := 0 * time.Second
		if allowWait {
			timeout = 25 * time.Second
		}
		return v2.Success(req.ID, gin.H{
			"events": agent_runtime.WaitV2Events(uuid, params.AckEventIDs, timeout),
		})
	case v2.MethodAgentFileResult:
		var params v2.FileResult
		if err := bindV2Params(req.Params, &params); err != nil {
			return v2.Error(req.ID, -32602, "invalid file result params", err.Error())
		}
		params.UUID = uuid
		if !filemanager.Resolve(params) {
			return v2.Error(req.ID, -32004, "unknown or expired file operation", nil)
		}
		return v2.Success(req.ID, gin.H{"status": "success"})
	case v2.MethodAgentStartupConfigResult:
		var params v2.StartupConfigResult
		if err := bindV2Params(req.Params, &params); err != nil {
			return v2.Error(req.ID, -32602, "invalid startup configuration result", nil)
		}
		if !agent_runtime.ResolveStartupConfig(uuid, params) {
			return v2.Error(req.ID, -32004, "unknown or expired startup configuration request", nil)
		}
		return v2.Success(req.ID, gin.H{"status": "success"})
	default:
		return v2.Error(req.ID, -32601, "method not found", req.Method)
	}
}

func UploadV2RPC(c *gin.Context) {
	bytesBody, err := readMaybeCompressedBody(c.Writer, c.Request)
	if err != nil {
		c.JSON(bodyReadErrorStatus(err), v2.Error(nil, -32700, "invalid compressed body", err.Error()))
		return
	}
	var req v2.Request
	if err := json.Unmarshal(bytesBody, &req); err != nil {
		c.JSON(http.StatusBadRequest, v2.Error(nil, -32700, "parse error", err.Error()))
		return
	}
	uuid, ok := clientUUIDFromContext(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, v2.Error(req.ID, -32001, "invalid token", nil))
		return
	}
	resp := handleV2RPC(uuid, req, true)
	status := http.StatusOK
	if resp.Error != nil {
		status = http.StatusBadRequest
	}
	c.JSON(status, resp)
}

func WebSocketV2RPC(c *gin.Context) {
	if !api.IsWebSocketUpgrade(c) {
		c.JSON(http.StatusBadRequest, gin.H{"status": "error", "error": "Require WebSocket upgrade"})
		return
	}
	// Compression is deliberately NOT negotiated here. gorilla/websocket
	// enforces SetReadLimit against the wire frame length, before
	// decompression, so a small permessage-deflate frame could still expand
	// into a multi-gigabyte ReadMessage buffer. Without compression the read
	// limit bounds the actual message size.
	conn, err := api.UpgradeSafeConn(c)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"status": "error", "error": "Failed to upgrade to WebSocket." + err.Error()})
		return
	}
	defer conn.Close()
	// Bound inbound messages before the read loop starts. With compression
	// disabled above, this limit counts the real (decompressed) message size.
	conn.GetConn().SetReadLimit(maxAgentWSMessage)

	uuid, ok := clientUUIDFromContext(c)
	if !ok {
		conn.WriteJSON(v2.Error(nil, -32001, "invalid token", nil))
		return
	}
	if oldConn, exists := agent_runtime.GetConnectedClients()[uuid]; exists {
		go oldConn.Close()
	}
	agent_runtime.SetConnectedClients(uuid, conn)
	agent_runtime.MarkV2Client(uuid)
	go notifierOnline(uuid, conn.ID)
	defer func() {
		agent_runtime.DeleteClientConditionally(uuid, conn)
		notifierOffline(uuid, conn.ID)
	}()
	if !pushQueuedV2Events(conn, uuid) {
		return
	}
	setWebSocketPingHandler(conn, v2WebSocketReadWait, v2WebSocketWriteWait)

	for {
		conn.SetReadDeadline(time.Now().Add(v2WebSocketReadWait))
		_, message, err := conn.ReadMessage()
		if err != nil {
			if errors.Is(err, websocket.ErrReadLimit) {
				logger.Errorf("client-api", "Client %s v2 message exceeded %d byte limit", uuid, maxAgentWSMessage)
			} else if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				logger.Errorf("client-api", "Client %s v2 heartbeat timed out after %s", uuid, v2WebSocketReadWait)
			} else if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				logger.Errorf("client-api", "Client %s v2 connection error: %v", uuid, err)
			}
			return
		}
		message = bytes.TrimSpace(message)
		var req v2.Request
		if err := json.Unmarshal(message, &req); err != nil {
			conn.WriteJSON(v2.Error(nil, -32700, "parse error", err.Error()))
			continue
		}
		resp := handleV2RPC(uuid, req, false)
		if req.ID != nil {
			if err := conn.WriteJSON(resp); err != nil {
				logger.Errorf("client-api", "failed to write v2 rpc response: %v", err)
				return
			}
		}
	}
}

func pushQueuedV2Events(conn *connection.SafeConn, uuid string) bool {
	events := agent_runtime.TakeV2Events(uuid, nil, 0)
	if len(events) == 0 {
		return true
	}
	ackIDs := make([]string, 0, len(events))
	for _, event := range events {
		payload := v2.Request{JSONRPC: v2.Version, Method: event.Method, Params: event.Params}
		if err := conn.WriteJSON(payload); err != nil {
			agent_runtime.AckV2Events(uuid, ackIDs)
			logger.Errorf("client-api", "failed to push queued v2 event %s to client %s: %v", event.ID, uuid, err)
			return false
		}
		ackIDs = append(ackIDs, event.ID)
	}
	agent_runtime.AckV2Events(uuid, ackIDs)
	return true
}

func clientUUIDFromContext(c *gin.Context) (string, bool) {
	if v, ok := c.Get("client_uuid"); ok {
		if uuid, ok := v.(string); ok && uuid != "" {
			return uuid, true
		}
	}
	token := c.Query("token")
	if token == "" {
		return "", false
	}
	uuid, err := clients.GetClientUUIDByToken(token)
	return uuid, err == nil && uuid != ""
}

func notifierOnline(uuid string, connID int64) {
	go func() {
		defer func() { _ = recover() }()
		notifier.OnlineNotification(uuid, connID)
	}()
}

func notifierOffline(uuid string, connID int64) {
	defer func() { _ = recover() }()
	notifier.OfflineNotification(uuid, connID)
}
