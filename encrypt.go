package main

/*
#cgo pkg-config: openssl
#include <openssl/bio.h>
#include <openssl/cms.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/evp.h>
#include <stdlib.h>

long MACRO_BIO_get_mem_data(BIO *b, char **pp) {
	return BIO_get_mem_data(b, pp);
}
*/
import "C"
import (
	"crypto/x509"
	"errors"
	"fmt"
	"unsafe"
)

func bytesFromBio(bio *C.BIO) ([]byte, error) {
	var ptr *C.char
	size := C.MACRO_BIO_get_mem_data(bio, &ptr)
	if size <= 0 {
		return nil, errors.New("no output data")
	}
	return C.GoBytes(unsafe.Pointer(ptr), C.int(size)), nil
}

// helper: load X509 cert from bytes
func loadCert(cert *x509.Certificate) (*C.X509, error) {
	if cert == nil || len(cert.Raw) == 0 {
		return nil, errors.New("invalid certificate input")
	}

	certLength := C.long(len(cert.Raw))
	ptr := (*C.uchar)(C.CBytes(cert.Raw))
	defer C.free(unsafe.Pointer(ptr))

	cCert := C.d2i_X509(nil, &ptr, certLength)
	if cCert == nil {
		return nil, fmt.Errorf("error parsing DER certificate: %w", getOpenSSLError())
	}

	return cCert, nil
}

// helper: pull OpenSSL errors
func getOpenSSLError() error {
	errCode := C.ERR_get_error()
	if errCode == 0 {
		return nil
	}
	errStr := C.ERR_error_string(errCode, nil)
	return errors.New(C.GoString(errStr))
}

// EncryptCMS tbd.
func EncryptCMS(data []byte, recipient *x509.Certificate) ([]byte, error) {
	// Initialize CMS structure. No recipient and data is passed since we are in CMS_PARTIAL mode allowing us for great
	// control over the process. CMS_add1_recipient_cert and CMS_final is called later to add recipients and data.
	cms := C.CMS_encrypt(nil, nil, C.EVP_aes_128_gcm(), C.CMS_PARTIAL|C.CMS_BINARY)
	if cms == nil {
		return nil, fmt.Errorf("CMS_encrypt failed: %w", getOpenSSLError())
	}
	defer C.CMS_ContentInfo_free(cms)

	cert, err := loadCert(recipient)
	if err != nil {
		return nil, fmt.Errorf("load cert: %w", err)
	}
	defer C.X509_free(cert)

	// Add recipient
	if C.CMS_add1_recipient_cert(cms, cert, 0) == nil {
		return nil, fmt.Errorf("CMS_add1_recipient_cert failed: %w", getOpenSSLError())
	}

	bioIn := C.BIO_new_mem_buf(unsafe.Pointer(&data[0]), C.int(len(data)))
	if bioIn == nil {
		return nil, errors.New("failed to create input BIO")
	}
	defer C.BIO_free(bioIn)

	// CMS_final will normally be called when the CMS_PARTIAL flag is used. It should only be used when streaming
	// is not performed because the streaming I/O functions perform finalization operations internally.
	if C.CMS_final(cms, bioIn, nil, 0) != 1 {
		return nil, fmt.Errorf("CMS_final failed: %w", getOpenSSLError())
	}

	// Output BIO
	bioOut := C.BIO_new(C.BIO_s_mem())
	if bioOut == nil {
		return nil, errors.New("failed to create output BIO")
	}
	defer C.BIO_free(bioOut)

	// BIO_new_CMS for BER encoding
	if C.PEM_write_bio_CMS_stream(bioOut, cms, nil, 0) != 1 {
		return nil, fmt.Errorf("i2d_CMS_bio_stream failed: %w", getOpenSSLError())
	}

	return bytesFromBio(bioOut)
}
