// Package secconf implements secconf encoding as specified in the following
// format:
//
//   base64(gpg(gzip(data)))
//
package secconf

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"strings"

	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/ssh/terminal"

	keyctl "github.com/jsipprell/keyctl/openpgp"
)

type EntityFilter interface {
	Entities(...*openpgp.Entity) openpgp.EntityList
}

type filterKeys struct {
	index      int
	EntityList openpgp.EntityList
}

func (fk *filterKeys) filter(keys []openpgp.Key, symmetric bool) ([]byte, error) {
	var keyid string
	var k openpgp.Key

	for keyid == "" {
		if fk.index >= len(keys) {
			return nil, io.EOF
		}

		k = keys[fk.index]
		fk.index++
		if k.PublicKey != nil {
			if keyid = k.PublicKey.KeyIdShortString(); keyid != "" {
				break
			}
		}
	}

	fd := int(os.Stdin.Fd())
	state, err := terminal.MakeRaw(fd)
	if err != nil {
		return nil, err
	}
	defer terminal.Restore(fd, state)

	t := terminal.NewTerminal(os.Stdin, "> ")
	pw, err := t.ReadPassword(fmt.Sprintf("Enter the passphrase for %v: ", keyid))
	if err != nil {
		return nil, err
	}

	if symmetric {
		return []byte(strings.TrimSpace(pw)), nil
	}
	if k.PrivateKey.Encrypted {
		if err := k.PrivateKey.Decrypt([]byte(strings.TrimSpace(pw))); err != nil {
			return nil, err
		}
	}
	return nil, nil
}

// Deocde decodes data using the secconf codec.
func DecodeVia(data []byte, secertKeyring io.Reader, p keyctl.PassphraseKeyring) ([]byte, error) {
	decoder := base64.NewDecoder(base64.StdEncoding, bytes.NewBuffer(data))
	entityList, err := openpgp.ReadKeyRing(secertKeyring)
	if err != nil {
		return nil, err
	}

	md, err := p.ReadMessage(decoder, entityList, nil, nil)
	if err != nil {
		return nil, err
	}
	gzReader, err := gzip.NewReader(md.UnverifiedBody)
	if err != nil {
		return nil, err
	}
	defer gzReader.Close()
	bytes, err := ioutil.ReadAll(gzReader)
	if err != nil {
		return nil, err
	}
	return bytes, nil
}

// Deocde decodes data using the secconf codec.
func Decode(data []byte, secertKeyring io.Reader) ([]byte, error) {
	decoder := base64.NewDecoder(base64.StdEncoding, bytes.NewBuffer(data))
	entityList, err := openpgp.ReadKeyRing(secertKeyring)
	if err != nil {
		return nil, err
	}

	md, err := openpgp.ReadMessage(decoder, entityList, (&filterKeys{EntityList: entityList}).filter, nil)
	if err != nil {
		return nil, err
	}
	gzReader, err := gzip.NewReader(md.UnverifiedBody)
	if err != nil {
		return nil, err
	}
	defer gzReader.Close()
	bytes, err := ioutil.ReadAll(gzReader)
	if err != nil {
		return nil, err
	}
	return bytes, nil
}

// Encode encodes data to a base64 encoded using the secconf codec.
// data is encrypted with all public keys found in the supplied keyring.
func Encode(data []byte, keyring io.Reader) ([]byte, error) {
	entityList, err := openpgp.ReadKeyRing(keyring)
	if err != nil {
		return nil, err
	}
	return encode(data, entityList)
}

func EncodeWith(data []byte, keyring io.Reader, f EntityFilter) ([]byte, error) {
	entityList, err := openpgp.ReadKeyRing(keyring)
	if err != nil {
		return nil, err
	}

	return encode(data, f.Entities(entityList...))
}

func encode(data []byte, entityList openpgp.EntityList) ([]byte, error) {
	buffer := new(bytes.Buffer)
	encoder := base64.NewEncoder(base64.StdEncoding, buffer)
	pgpWriter, err := openpgp.Encrypt(encoder, entityList, nil, &openpgp.FileHints{IsBinary: true, FileName: "_CONSOLE"}, nil)
	if err != nil {
		return nil, err
	}
	gzWriter := gzip.NewWriter(pgpWriter)
	if _, err := gzWriter.Write(data); err != nil {
		return nil, err
	}
	if err := gzWriter.Close(); err != nil {
		return nil, err
	}
	if err := pgpWriter.Close(); err != nil {
		return nil, err
	}
	if err := encoder.Close(); err != nil {
		return nil, err
	}
	return buffer.Bytes(), nil
}
