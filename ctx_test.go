// Copyright (C) 2017. See AUTHORS.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package openssl

import (
	"testing"
	"time"
)

func TestCtxTimeoutOption(t *testing.T) {
	ctx, _ := NewCtx()
	oldTimeout1 := ctx.GetTimeout()
	newTimeout1 := oldTimeout1 + (time.Duration(99) * time.Second)
	oldTimeout2 := ctx.SetTimeout(newTimeout1)
	newTimeout2 := ctx.GetTimeout()
	if oldTimeout1 != oldTimeout2 {
		t.Error("SetTimeout() returns something undocumented")
	}
	if newTimeout1 != newTimeout2 {
		t.Error("SetTimeout() does not save anything to ctx")
	}
}

func TestCtxSessCacheSizeOption(t *testing.T) {
	ctx, _ := NewCtx()
	oldSize1 := ctx.SessGetCacheSize()
	newSize1 := oldSize1 + 42
	oldSize2 := ctx.SessSetCacheSize(newSize1)
	newSize2 := ctx.SessGetCacheSize()
	if oldSize1 != oldSize2 {
		t.Error("SessSetCacheSize() returns something undocumented")
	}
	if newSize1 != newSize2 {
		t.Error("SessSetCacheSize() does not save anything to ctx")
	}
}

func TestCtxSetDefaultVerifyLocations(t *testing.T) {
	ctx, err := NewCtx()
	if err != nil {
		t.Error("cant create context")
	}

	conn, err := Dial("tcp", "google.com:443", ctx, 0)
	if conn == nil || err != nil {
		t.Skip("can't connect, skipping the test.")
	}
	v := conn.VerifyResult()

	if v != UnableToGetIssuerCertLocally {
		t.Errorf("expected: UnableToGetIssuerCertLocally, got: %d", v)
	}

	ctx, err = NewCtx()
	if err != nil {
		t.Error("cant create context")
	}

	if err := ctx.SetDefaultVerifyPaths(); err != nil {
		t.Errorf("set_default_verify_paths OpenSSL call failed: %v", err)
	}

	conn, err = Dial("tcp", "google.com:443", ctx, 0)
	v = conn.VerifyResult()

	if v != Ok {
		t.Errorf("expected: Ok, got: %d", v)
	}
}

// TestGetDefaultCertificateDirectory returns the default directory for CA
// certificates on the system.
func TestGetDefaultCertificateDirectory(t *testing.T) {
	defDir, err := GetDefaultCertificateDirectory()
	if err != nil {
		t.Errorf("Failed to get the default certificate directory. '%v'", err)
	}

	if len(defDir) == 0 {
		t.Errorf("Error: GetDefaultCertificateDirectory() returned a zero length string, but no error")
	}
}
