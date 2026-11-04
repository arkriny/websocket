// Copyright 2015 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package websocket

import (
	"context"
	"crypto/tls"
	"net"
)

func dialWithDialer(ctx context.Context, dialer *net.Dialer, config *Config) (net.Conn, error) {
	switch config.Location.Scheme {
	case "ws":
		return dialer.DialContext(ctx, "tcp", parseAuthority(config.Location))

	case "wss":
		tlsDialer := &tls.Dialer{
			NetDialer: dialer,
			Config:    config.TlsConfig,
		}
		return tlsDialer.DialContext(ctx, "tcp", parseAuthority(config.Location))
	default:
		return nil, ErrBadScheme
	}
}
