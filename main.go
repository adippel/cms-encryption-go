package main

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"os"
)

type opts struct {
	CertificatePath string
	Message         string
	OutFile         string
}

func Run(options opts) error {
	// Read the certificate from the given path
	certPEM, err := os.ReadFile(options.CertificatePath)
	if err != nil {
		return fmt.Errorf("failed to read certificate: %w", err)
	}

	// Decode the PEM block
	block, _ := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		return errors.New("error to decode PEM block containing certificate")
	}

	// Parse the certificate
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("error parsing certificate: %w", err)
	}

	// Perform encryption for the recipient
	encrypted, err := EncryptCMS([]byte(options.Message), cert)
	if err != nil {
		return err
	}

	// Output the CMS structure as file or on stdout
	if options.OutFile != "" {
		fd, err := os.OpenFile(options.OutFile, os.O_WRONLY|os.O_CREATE, 0644)
		if err != nil {
			return err
		}
		defer fd.Close()

		_, err = fd.Write(encrypted)
		fmt.Println("Wrote CMS content to file:", options.OutFile)
		return err
	} else {
		fmt.Println("Encrypted using CMS:")
		fmt.Println(string(encrypted))
	}

	return err
}

func main() {
	var options opts
	flag.StringVar(&options.CertificatePath, "cert", "", "Certificate path")
	flag.StringVar(&options.Message, "message", "", "Message to encrypt")
	flag.StringVar(&options.OutFile, "out", "", "Output file")
	flag.Parse()

	if options.CertificatePath == "" {
		fmt.Println("missing required argument: -cert")
		return
	}
	if options.Message == "" {
		fmt.Println("missing required argument: -message")
		return
	}

	err := Run(options)
	if err != nil {
		fmt.Println("Error running the command:", err)
	}

	return
}
