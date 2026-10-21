package plugin

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/dop251/goja"
	"github.com/komari-monitor/komari/pkg/rpc"
)

// reservedMethodNamespaces lists method-name prefixes owned by built-in RPC
// namespaces. A plugin must not register a method under them: doing so would
// let it shadow or impersonate a host method (for example by claiming an
// "admin:..." method is only guest-accessible, or by squatting on a name the
// host expects to provide).
var reservedMethodNamespaces = []string{"admin", "common", "guest", "rpc", "client"}

// validatePluginMethodName rejects empty method names and names that collide
// with a built-in namespace. Wildcards are also rejected: every plugin method
// becomes an exact ACL rule, and a '*' in the name would otherwise be
// interpreted as an ACL wildcard (for example "plugin:*" would widen access to
// every other plugin method).
func validatePluginMethodName(method string) error {
	if method == "" || strings.HasPrefix(method, "rpc.") {
		return fmt.Errorf("invalid RPC method name %q", method)
	}
	if strings.ContainsRune(method, '*') {
		return fmt.Errorf("invalid RPC method name %q: '*' is not allowed in plugin method names", method)
	}
	for _, namespace := range reservedMethodNamespaces {
		if strings.HasPrefix(method, namespace+":") {
			return fmt.Errorf("invalid RPC method name %q: the %q namespace is reserved for built-in methods", method, namespace)
		}
	}
	return nil
}

// registerRPC registers a plugin-owned RPC method. The handler is a
// JavaScript function receiving the JSON-RPC params, a read-only call-context
// object, and returning the result (or throwing an Error with optional
// code/data). Called from the plugin's own event loop during script
// evaluation; it takes the manager lock itself.
//
// Every plugin method is declared admin-only at the RPC boundary unless the
// plugin manifest lists it in public_rpc, in which case anonymous visitors may
// call it. The method name may not use a built-in namespace (admin:, common:,
// guest:, rpc:, client:).
func (m *Manager) registerRPC(short, method string, handler goja.Callable) error {
	method = strings.TrimSpace(method)
	if err := validatePluginMethodName(method); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	inst, ok := m.instances[short]
	if !ok {
		return fmt.Errorf("plugin %q is not loaded", short)
	}
	inst.mu.Lock()
	if inst.rpcMethods == nil {
		inst.rpcMethods = make(map[string]goja.Callable)
	}
	if _, exists := inst.rpcMethods[method]; exists {
		inst.mu.Unlock()
		return nil // already registered in this load
	}
	inst.rpcMethods[method] = handler
	inst.mu.Unlock()
	if err := rpc.Register(method, m.rpcHandler(short, method)); err != nil {
		inst.mu.Lock()
		delete(inst.rpcMethods, method)
		inst.mu.Unlock()
		return err
	}
	// Declare the ACL only after the handler is accepted, so a duplicate name
	// owned by another method never mutates that method's permission. Bare
	// names are normalized into the default namespace so the exact rule beats
	// the permissive "common:*" fallback.
	rpc.Allow(rpc.NormalizeMethodName(method), pluginMethodRole(inst.info.PublicRPC, method))
	return nil
}

// pluginMethodRole returns the minimum role a plugin method requires. Methods
// explicitly listed in the manifest's public_rpc are open to guests; every
// other plugin method requires admin.
func pluginMethodRole(publicRPC []string, method string) string {
	for _, name := range publicRPC {
		if strings.TrimSpace(name) == method {
			return rpc.RoleGuest
		}
	}
	return rpc.RoleAdmin
}

// rpcHandler bridges one registered RPC call into the plugin event loop.
func (m *Manager) rpcHandler(short, method string) rpc.Handler {
	return func(ctx context.Context, req *rpc.JsonRpcRequest) (any, *rpc.JsonRpcError) {
		inst := m.instanceFor(short)
		if inst == nil {
			return nil, &rpc.JsonRpcError{Code: rpc.Unavailable, Message: fmt.Sprintf("plugin %q is not loaded", short)}
		}
		inst.mu.RLock()
		handler := inst.rpcMethods[method]
		host := inst.host
		alive := inst.runtime != nil
		inst.mu.RUnlock()
		if !alive || handler == nil || host == nil {
			return nil, &rpc.JsonRpcError{Code: rpc.MethodNotFound, Message: "method not found", Data: method}
		}

		resultCh := make(chan any, 1)
		errCh := make(chan *rpc.JsonRpcError, 1)
		meta := rpc.MetaFromContext(ctx)
		queued := host.RunOnLoop(func(vm *goja.Runtime) {
			_ = host.RunJob(vm, "plugin rpc "+method, func() error {
				params := vm.ToValue(req.Params)
				if params == nil {
					params = goja.Null()
				}
				callCtx := newRPCCallContext(vm, meta)
				value, callErr := handler(goja.Undefined(), params, callCtx)
				if callErr != nil {
					errCh <- jsErrorToRPCError(vm, callErr)
					return nil // error is captured, do not double-report
				}
				exported, exportErr := exportJSValue(value)
				if exportErr != nil {
					errCh <- &rpc.JsonRpcError{Code: rpc.InternalError, Message: exportErr.Error()}
					return nil
				}
				resultCh <- exported
				return nil
			})
		})
		if !queued {
			return nil, &rpc.JsonRpcError{Code: rpc.Unavailable, Message: "plugin runtime is closed"}
		}
		timer := time.NewTimer(host.Timeout())
		defer timer.Stop()
		select {
		case result := <-resultCh:
			return result, nil
		case rpcErr := <-errCh:
			return nil, rpcErr
		case <-timer.C:
			return nil, &rpc.JsonRpcError{Code: rpc.DeadlineExceeded, Message: "plugin RPC handler timed out"}
		}
	}
}

// newRPCCallContext builds the read-only identity object handed to a plugin
// RPC handler as its second argument:
//
//	handler(params, { role, userUUID, clientUUID, isAPIKey })
//
// The object reflects the authenticated caller of the current request. It is
// frozen so a plugin cannot tamper with the identity it was authorized with;
// plugins should treat it as an immutable snapshot.
func newRPCCallContext(vm *goja.Runtime, meta *rpc.ContextMeta) *goja.Object {
	role := rpc.RoleGuest
	userUUID := ""
	clientUUID := ""
	isAPIKey := false
	if meta != nil {
		if meta.Principal != nil {
			role = meta.Principal.PrimaryRole()
			userUUID = meta.Principal.UserUUID
			clientUUID = meta.Principal.ClientUUID
			isAPIKey = meta.Principal.IsAPIKey
		} else if meta.Permission != "" {
			role = meta.Permission
		}
		if meta.UserUUID != "" {
			userUUID = meta.UserUUID
		}
		if meta.ClientUUID != "" {
			clientUUID = meta.ClientUUID
		}
	}
	obj := vm.NewObject()
	_ = obj.Set("role", role)
	_ = obj.Set("userUUID", userUUID)
	_ = obj.Set("clientUUID", clientUUID)
	_ = obj.Set("isAPIKey", isAPIKey)
	freezeJSObject(vm, obj)
	return obj
}

// freezeJSObject freezes obj through the runtime's Object.freeze when the
// built-in is available, making the call-context snapshot read-only.
func freezeJSObject(vm *goja.Runtime, obj *goja.Object) {
	ctor := vm.Get("Object")
	if ctor == nil || goja.IsUndefined(ctor) || goja.IsNull(ctor) {
		return
	}
	freeze, ok := goja.AssertFunction(ctor.ToObject(vm).Get("freeze"))
	if !ok {
		return
	}
	_, _ = freeze(goja.Undefined(), obj)
}

// exportJSValue exports a goja value into a JSON-RPC result. Circular
// structures and other export failures become an error instead of panicking
// inside the event loop.
func exportJSValue(value goja.Value) (result any, err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			result = nil
			err = fmt.Errorf("export JavaScript value: %v", recovered)
		}
	}()
	return value.Export(), nil
}

// jsErrorToRPCError converts a thrown JavaScript error into a JSON-RPC error,
// honoring optional code/data properties.
func jsErrorToRPCError(vm *goja.Runtime, err error) *rpc.JsonRpcError {
	code := rpc.InternalError
	message := err.Error()
	var data any
	var exception *goja.Exception
	if errors.As(err, &exception) {
		if obj, ok := exception.Value().(*goja.Object); ok {
			if value := obj.Get("code"); value != nil && !goja.IsUndefined(value) {
				if n := value.ToInteger(); n != 0 {
					code = int(n)
				}
			}
			if value := obj.Get("message"); value != nil && !goja.IsUndefined(value) && value.String() != "" {
				message = value.String()
			}
			if value := obj.Get("data"); value != nil && !goja.IsUndefined(value) {
				if exported, exportErr := exportJSValue(value); exportErr == nil {
					data = exported
				}
			}
		}
	}
	return &rpc.JsonRpcError{Code: code, Message: message, Data: data}
}
