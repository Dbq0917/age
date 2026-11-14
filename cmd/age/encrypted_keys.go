// Copyright 2019 The age Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"filippo.io/age"
	"filippo.io/age/internal/term"
)

// defaultMaxScryptWorkFactor is the maximum scrypt work factor (logN)
// accepted without interactive confirmation. It matches the default of
// age.ScryptIdentity (see NewScryptIdentity). It's a variable so it can be
// lowered in tests.
var defaultMaxScryptWorkFactor = 22

// absoluteMaxScryptWorkFactor is the highest work factor that
// age.ScryptRecipient can encode (see SetWorkFactor). Files with a higher
// work factor are rejected unconditionally, as they would take unreasonable
// resources to decrypt even with user confirmation.
const absoluteMaxScryptWorkFactor = 30

// LazyScryptIdentity is an age.Identity that requests a passphrase only if it
// encounters an scrypt stanza. After obtaining a passphrase, it delegates to
// ScryptIdentity.
type LazyScryptIdentity struct {
	Passphrase func() (string, error)
}

var _ age.Identity = &LazyScryptIdentity{}

func (i *LazyScryptIdentity) Unwrap(stanzas []*age.Stanza) (fileKey []byte, err error) {
	for _, s := range stanzas {
		if s.Type == "scrypt" && len(stanzas) != 1 {
			return nil, errors.New("an scrypt recipient must be the only one")
		}
	}
	if len(stanzas) != 1 || stanzas[0].Type != "scrypt" {
		return nil, age.ErrIncorrectIdentity
	}
	maxWorkFactor, err := checkScryptWorkFactor(stanzas[0])
	if err != nil {
		return nil, err
	}
	pass, err := i.Passphrase()
	if err != nil {
		return nil, fmt.Errorf("could not read passphrase: %v", err)
	}
	ii, err := age.NewScryptIdentity(pass)
	if err != nil {
		return nil, err
	}
	if maxWorkFactor != 0 {
		ii.SetMaxWorkFactor(maxWorkFactor)
	}
	fileKey, err = ii.Unwrap(stanzas)
	if errors.Is(err, age.ErrIncorrectIdentity) {
		// ScryptIdentity returns ErrIncorrectIdentity for an incorrect
		// passphrase, which would lead Decrypt to returning "no identity
		// matched any recipient". That makes sense in the API, where there
		// might be multiple configured ScryptIdentity. Since in cmd/age there
		// can be only one, return a better error message.
		return nil, fmt.Errorf("incorrect passphrase")
	}
	return fileKey, err
}

// checkScryptWorkFactor inspects the work factor of an scrypt stanza. If it
// exceeds the default maximum, the file was probably encrypted before the
// current limit was introduced, and the user is asked to confirm the slower
// decryption. It returns the maximum work factor to set on the identity, or
// zero to use the library default.
func checkScryptWorkFactor(s *age.Stanza) (int, error) {
	if len(s.Args) != 2 {
		// Let the library return a proper error.
		return 0, nil
	}
	logN, err := strconv.Atoi(s.Args[1])
	if err != nil {
		// Let the library return a proper error.
		return 0, nil
	}
	if logN > absoluteMaxScryptWorkFactor {
		return 0, fmt.Errorf("scrypt work factor too large: %d", logN)
	}
	if logN <= defaultMaxScryptWorkFactor {
		return 0, nil
	}
	warningf("file uses a high scrypt work factor (2^%d), decryption may be very slow", logN)
	// ReadSecret is used instead of ReadPublic because the latter buffers
	// more than one line of input, which would swallow the passphrase if it
	// was already typed or piped to the terminal.
	answer, err := term.ReadSecret("Decrypt anyway? [y/N]")
	if err != nil {
		return 0, fmt.Errorf("scrypt work factor too large: %d (to decrypt non-interactively, use the batchpass plugin with AGE_PASSPHRASE_MAX_WORK_FACTOR=%d)", logN, logN)
	}
	if a := strings.ToLower(strings.TrimSpace(string(answer))); a != "y" && a != "yes" {
		return 0, fmt.Errorf("scrypt work factor too large: %d", logN)
	}
	return logN, nil
}

type EncryptedIdentity struct {
	Contents       []byte
	Passphrase     func() (string, error)
	NoMatchWarning func()

	identities []age.Identity
}

var _ age.Identity = &EncryptedIdentity{}

func (i *EncryptedIdentity) Recipients() ([]age.Recipient, error) {
	if i.identities == nil {
		if err := i.decrypt(); err != nil {
			return nil, err
		}
	}

	return identitiesToRecipients(i.identities)
}

func (i *EncryptedIdentity) Unwrap(stanzas []*age.Stanza) (fileKey []byte, err error) {
	if i.identities == nil {
		if err := i.decrypt(); err != nil {
			return nil, err
		}
	}

	for _, id := range i.identities {
		fileKey, err = id.Unwrap(stanzas)
		if errors.Is(err, age.ErrIncorrectIdentity) {
			continue
		}
		if err != nil {
			return nil, err
		}
		return fileKey, nil
	}
	i.NoMatchWarning()
	return nil, age.ErrIncorrectIdentity
}

func (i *EncryptedIdentity) decrypt() error {
	d, err := age.Decrypt(bytes.NewReader(i.Contents), &LazyScryptIdentity{i.Passphrase})
	if e := new(age.NoIdentityMatchError); errors.As(err, &e) {
		return fmt.Errorf("identity file is encrypted with age but not with a passphrase")
	}
	if err != nil {
		return fmt.Errorf("failed to decrypt identity file: %v", err)
	}
	i.identities, err = parseIdentities(d)
	return err
}
