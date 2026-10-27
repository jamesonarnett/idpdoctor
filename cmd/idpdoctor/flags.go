// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/jamesonarnett/idpdoctor/internal/expected"
	"github.com/jamesonarnett/idpdoctor/internal/jwt"
)

// inputFlags is how every subcommand receives its artifact: a file, an
// inline string, or stdin. Nothing is ever written back to disk.
type inputFlags struct {
	file   string
	inline string
}

func (f *inputFlags) bind(cmd *cobra.Command) {
	cmd.Flags().StringVarP(&f.file, "file", "f", "", "read the artifact from this file ('-' for stdin)")
	cmd.Flags().StringVar(&f.inline, "input", "", "the artifact itself (prefer --file; shell history is a log)")
}

func (f *inputFlags) read(cmd *cobra.Command) (string, error) {
	switch {
	case f.inline != "":
		return f.inline, nil
	case f.file == "-":
		b, err := io.ReadAll(cmd.InOrStdin())
		return string(b), err
	case f.file != "":
		b, err := os.ReadFile(f.file)
		return string(b), err
	}
	return "", errors.New("provide --file or --input")
}

// expectedFlags binds the Expected object to flags. The flag names match
// the JSON field names so the CLI and the MCP schema read the same.
type expectedFlags struct {
	exp                    expected.Expected
	idpCertFile            string
	requireSignedAssertion bool
	requireSignedResponse  bool
	keys                   jwt.Keys
	jwksFile               string
	pemFile                string
}

func (f *expectedFlags) bindSAML(cmd *cobra.Command) {
	fs := cmd.Flags()
	fs.StringVar(&f.exp.SPEntityID, "sp-entity-id", "", "SP entity ID the Audience must equal")
	fs.StringVar(&f.exp.ACSURL, "acs-url", "", "SP ACS URL Destination and Recipient must equal")
	fs.StringVar(&f.exp.IdPEntityID, "idp-entity-id", "", "IdP entityID the Issuer must equal")
	fs.StringVar(&f.idpCertFile, "idp-cert", "", "file holding the IdP signing certificate (PEM or metadata base64)")
	fs.StringVar(&f.exp.RequestID, "request-id", "", "AuthnRequest ID that InResponseTo must echo")
	fs.StringVar(&f.exp.NameIDFormat, "name-id-format", "", "NameID Format URN the SP expects")
	fs.StringSliceVar(&f.exp.RequiredAttributes, "required-attr", nil, "attribute Name the SP needs (repeatable)")
	fs.BoolVar(&f.requireSignedAssertion, "require-signed-assertion", false, "the SP requires a signed Assertion")
	fs.BoolVar(&f.requireSignedResponse, "require-signed-response", false, "the SP requires a signed Response")
}

func (f *expectedFlags) bindJWT(cmd *cobra.Command) {
	fs := cmd.Flags()
	fs.StringVar(&f.exp.Issuer, "issuer", "", "exact iss the OP publishes")
	fs.StringVar(&f.exp.ClientID, "client-id", "", "this client's ID (aud must contain it)")
	fs.StringVar(&f.exp.Audience, "audience", "", "audience to require instead of client-id")
	fs.StringVar(&f.exp.Nonce, "nonce", "", "nonce sent in the authorization request")
	fs.StringSliceVar(&f.exp.AllowedAlgs, "allowed-alg", nil, "allowed signing algorithm (repeatable; default asymmetric set)")
	fs.StringVar(&f.jwksFile, "jwks", "", "file holding the JWKS JSON")
	fs.StringVar(&f.keys.JWKSURL, "jwks-url", "", "fetch the JWKS from this URL (the only network call)")
	fs.StringVar(&f.pemFile, "pem", "", "file holding a PEM public key or certificate")
}

// bindClock is bound once per command (diagnose binds SAML and JWT flags).
func (f *expectedFlags) bindClock(cmd *cobra.Command) {
	cmd.Flags().StringVar(&f.exp.Now, "now", "", "RFC 3339 time to validate at (replay a capture at its capture time)")
	cmd.Flags().IntVar(&f.exp.ClockSkewSeconds, "skew", 0, "clock skew tolerance in seconds (default 180, max 300)")
}

// resolve reads the file-backed flags and finalises Expected and Keys.
func (f *expectedFlags) resolve(cmd *cobra.Command) (expected.Expected, jwt.Keys, error) {
	if f.idpCertFile != "" {
		b, err := os.ReadFile(f.idpCertFile)
		if err != nil {
			return f.exp, f.keys, fmt.Errorf("--idp-cert: %w", err)
		}
		f.exp.IdPCertPEM = string(b)
	}
	if f.jwksFile != "" {
		b, err := os.ReadFile(f.jwksFile)
		if err != nil {
			return f.exp, f.keys, fmt.Errorf("--jwks: %w", err)
		}
		f.keys.JWKSJSON = string(b)
	}
	if f.pemFile != "" {
		b, err := os.ReadFile(f.pemFile)
		if err != nil {
			return f.exp, f.keys, fmt.Errorf("--pem: %w", err)
		}
		f.keys.PEM = string(b)
	}
	// Only set the pointers when the user said so; nil means "not stated".
	if cmd.Flags().Changed("require-signed-assertion") {
		v := f.requireSignedAssertion
		f.exp.RequireSignedAssertion = &v
	}
	if cmd.Flags().Changed("require-signed-response") {
		v := f.requireSignedResponse
		f.exp.RequireSignedResponse = &v
	}
	return f.exp, f.keys, nil
}

// outputFlags selects JSON or text and an optional output file.
type outputFlags struct {
	json bool
	out  string
}

func (f *outputFlags) bind(cmd *cobra.Command) {
	cmd.Flags().BoolVar(&f.json, "json", false, "print the full redacted JSON instead of the text summary")
	cmd.Flags().StringVar(&f.out, "out", "", "write the output to this file instead of stdout")
}

func (f *outputFlags) write(cmd *cobra.Command, text string, v any) error {
	w := cmd.OutOrStdout()
	if f.out != "" {
		fh, err := os.Create(f.out)
		if err != nil {
			return err
		}
		defer fh.Close()
		w = fh
	}
	if f.json {
		return writeJSON(w, v)
	}
	_, err := io.WriteString(w, strings.TrimRight(text, "\n")+"\n")
	return err
}
