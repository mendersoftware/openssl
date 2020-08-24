package openssl

// #include <shim.h>
import "C"

import (
	"bytes"
	"errors"
	"io"
	"reflect"
	"runtime"
	"sync"
	"unsafe"
)

const SSLRecordSize = 16 * 1024

func goBytes(p unsafe.Pointer, size int) []byte {
	var ret []byte
	hdr := (*reflect.SliceHeader)(unsafe.Pointer(&ret))
	hdr.Cap = size
	hdr.Len = size
	hdr.Data = uintptr(p)
	return ret
}

// newWriteBIO creates a new internal IO interface (BIO) with openssl for
// writing across the Go/cgo boundary.
// NOTE: As a finalizer, the pointer no longer becomes reachable from C's write
// interface, but is NOT freed either. The reason being that the BIO is usually
// owned by an SSL structure immedeately after initializing a new bio.
type goBIO struct {
	bio *C.BIO
	buf bytes.Buffer
	mtx sync.RWMutex
	eof bool
}

func newGoBIO() *goBIO {
	ret := &goBIO{
		buf: bytes.Buffer{},
	}
	bio := C.X_BIO_new_go_bio()
	if bio == nil {
		return nil
	}
	C.X_BIO_set_data(bio, unsafe.Pointer(ret))
	ret.bio = bio
	runtime.SetFinalizer(ret, func(r *goBIO) {
		C.BIO_free_all(r.bio)
	})
	return ret
}

func (b *goBIO) WriteTo(w io.Writer) (n int64, err error) {
	b.mtx.RLock()
	defer b.mtx.RUnlock()
	return b.buf.WriteTo(w)
}

// ReadFromConn copies bytes from r into the bio buffer until
// an incomplete read is made, which indicates that the next
// read from a net.Conn will be blocking.
func (b *goBIO) ReadFromConn(r io.Reader) (n int, err error) {
	buf := make([]byte, SSLRecordSize)

	b.mtx.Lock()
	defer b.mtx.Unlock()
	L := len(buf)
	N := 0
	for {
		n, err = r.Read(buf)
		N += n
		if err != nil {
			return N, err
		}
		_, err = b.buf.Write(buf[:n])
		if err != nil || n < L {
			break
		}
	}

	return N, err
}

func (rb *goBIO) MarkEOF() {
	rb.mtx.Lock()
	defer rb.mtx.Unlock()
	rb.eof = true
}

func loadGoBIO(b *C.BIO) *goBIO {
	wb := unsafe.Pointer(C.X_BIO_get_data(b))
	return (*goBIO)(wb)
}

func bioClearRetryFlags(b *C.BIO) {
	C.X_BIO_clear_flags(b, C.BIO_FLAGS_RWS|C.BIO_FLAGS_SHOULD_RETRY)
}

func bioSetRetryRead(b *C.BIO) {
	C.X_BIO_set_flags(b, C.BIO_FLAGS_READ|C.BIO_FLAGS_SHOULD_RETRY)
}

//export go_bio_ctrl
func go_bio_ctrl(
	b *C.BIO,
	cmd C.int,
	larg C.long,
	parg unsafe.Pointer,
) (rc C.long) {
	defer func() {
		if r := recover(); r != nil {
			rc = -1
		}
	}()
	bio := loadGoBIO(b)
	if bio == nil {
		return -1
	}
	switch cmd {
	case C.BIO_CTRL_WPENDING, C.BIO_CTRL_PENDING:
		bio.mtx.RLock()
		ret := bio.buf.Len()
		bio.mtx.RUnlock()
		return C.long(ret)
	case C.BIO_CTRL_DUP, C.BIO_CTRL_FLUSH:
		return 1
	case C.BIO_CTRL_RESET:
		bio.mtx.Lock()
		bio.buf.Reset()
		bio.mtx.Unlock()
		return 1
	case C.BIO_CTRL_EOF:
		if bio.eof {
			return 1
		}
	}
	return 0
}

//export go_bio_read
func go_bio_read(b *C.BIO, p *C.char, size C.int) (rc C.int) {
	if p == nil || size <= 0 {
		return 0
	}
	defer func() {
		if r := recover(); r != nil {
			rc = -1
		}
	}()
	rb := loadGoBIO(b)
	rb.mtx.RLock()
	defer rb.mtx.RUnlock()
	bioClearRetryFlags(b)
	buf := goBytes(unsafe.Pointer(p), int(size))
	n, err := rb.buf.Read(buf)
	if err != nil {
		if err == io.EOF && rb.eof {
			return 0
		}
		bioSetRetryRead(b)
		return -1
	}
	return C.int(n)
}

//export go_bio_write
func go_bio_write(b *C.BIO, data *C.char, size C.int) (rc C.int) {
	if data == nil || size == 0 {
		return 0
	}
	defer func() {
		if r := recover(); r != nil {
			rc = -1
		}
	}()
	wb := loadGoBIO(b)
	wb.mtx.Lock()
	defer wb.mtx.Unlock()
	bioClearRetryFlags(b)
	buf := goBytes(unsafe.Pointer(data), int(size))
	n, err := wb.buf.Write(buf)
	if err != nil {
		return -1
	}
	return C.int(n)
}

type anyBio C.BIO

func asAnyBio(b *C.BIO) *anyBio { return (*anyBio)(b) }

func (b *anyBio) Read(buf []byte) (n int, err error) {
	if len(buf) == 0 {
		return 0, nil
	}
	n = int(C.X_BIO_read((*C.BIO)(b), unsafe.Pointer(&buf[0]), C.int(len(buf))))
	if n <= 0 {
		return 0, io.EOF
	}
	return n, nil
}

func (b *anyBio) Write(buf []byte) (written int, err error) {
	if len(buf) == 0 {
		return 0, nil
	}
	n := int(C.X_BIO_write((*C.BIO)(b), unsafe.Pointer(&buf[0]),
		C.int(len(buf))))
	if n != len(buf) {
		return n, errors.New("BIO write failed")
	}
	return n, nil
}
