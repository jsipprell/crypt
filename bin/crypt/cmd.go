package main

import (
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path"
	"strings"

	"github.com/jsipprell/crypt/backend"
	"github.com/jsipprell/crypt/backend/consul"
	"github.com/jsipprell/crypt/backend/etcd"
	"github.com/jsipprell/crypt/encoding/secconf"

	"golang.org/x/crypto/openpgp"
)

const nodeRoot = "secure/storage"

type pubkeyFilter []string

func (pk pubkeyFilter) Entities(ents ...*openpgp.Entity) openpgp.EntityList {
	el := make(openpgp.EntityList, 0, 1)

entityFilterLoop:
	for _, e := range ents {
		for _, id := range e.Identities {
			for _, k := range pk {
				if strings.Contains(id.Name, k) {
					el = append(el, e)

					break entityFilterLoop
				}
			}
		}
	}

	return el
}

func nodeKey(key string) string {
	return path.Join(nodeRoot, key)
}

func getCmd(flagset *flag.FlagSet) {
	flagset.Usage = func() {
		fmt.Fprintf(os.Stderr, "usage: %s get [args...] key\n", os.Args[0])
		flagset.PrintDefaults()
	}
	flagset.StringVar(&secretKeyring, "secret-keyring", DefaultConfig.SecretKeyring, "path to armored secret keyring")
	flagset.Parse(os.Args[2:])
	key := flagset.Arg(0)
	if key == "" {
		flagset.Usage()
		os.Exit(1)
	}
	backendStore, err := getBackendStore(backendName, endpoint)
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("Looking at consul node %q\n", nodeKey(key))
	if plaintext {
		value, err := getPlain(nodeKey(key), backendStore)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("%s\n", value)
		return
	}
	value, err := getEncrypted(nodeKey(key), secretKeyring, backendStore)

	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("%s\n", value)
}

func getEncrypted(key, keyring string, store backend.Store) ([]byte, error) {
	var value []byte
	kr, err := os.Open(secretKeyring)
	if err != nil {
		return value, err
	}
	defer kr.Close()
	data, err := store.Get(key)
	if err != nil {
		return value, err
	}
	value, err = secconf.Decode(data, kr)
	if err != nil {
		return value, err
	}
	return value, err

}

func getPlain(key string, store backend.Store) ([]byte, error) {
	var value []byte
	data, err := store.Get(key)
	if err != nil {
		return value, err
	}
	return data, err
}

func listCmd(flagset *flag.FlagSet) {
	flagset.Usage = func() {
		fmt.Fprintf(os.Stderr, "usage: %s list [args...] key\n", os.Args[0])
		flagset.PrintDefaults()
	}
	flagset.StringVar(&secretKeyring, "secret-keyring", DefaultConfig.SecretKeyring, "path to armored secret keyring")
	flagset.Parse(os.Args[2:])
	key := flagset.Arg(0)
	if key == "" {
		flagset.Usage()
		os.Exit(1)
	}
	backendStore, err := getBackendStore(backendName, endpoint)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("Looking for consul nodes under %q\n", nodeKey(key))
	if plaintext {
		list, err := listPlain(nodeKey(key), backendStore)
		if err != nil {
			log.Fatal(err)
		}
		for _, kv := range list {
			fmt.Printf("%s: %s", kv.Key, kv.Value)
		}
		return
	}
	list, err := listEncrypted(nodeKey(key), secretKeyring, backendStore)

	if err != nil {
		log.Fatal(err)
	}
	for _, kv := range list {
		fmt.Printf("%s: %s", kv.Key, kv.Value)
	}
}

func listEncrypted(key, keyring string, store backend.Store) (backend.KVPairs, error) {
	kr, err := os.Open(secretKeyring)
	if err != nil {
		return nil, err
	}
	defer kr.Close()

	data, err := store.List(key)
	if err != nil {
		return nil, err
	}
	for i, kv := range data {
		data[i].Value, err = secconf.Decode(kv.Value, kr)
		kr.Seek(0, 0)
		if err != nil {
			return nil, err
		}
	}
	return data, err
}

func listPlain(key string, store backend.Store) (backend.KVPairs, error) {
	data, err := store.List(key)
	if err != nil {
		return nil, err
	}
	return data, err
}

func setCmd(flagset *flag.FlagSet) {
	flagset.Usage = func() {
		fmt.Fprintf(os.Stderr, "usage: %s set [args...] key file\n", os.Args[0])
		flagset.PrintDefaults()
	}
	flagset.StringVar(&keyring, "keyring", DefaultConfig.Keyring, "path to armored public keyring")
	flagset.Parse(os.Args[2:])
	key := flagset.Arg(0)
	if key == "" {
		flagset.Usage()
		os.Exit(1)
	}
	keySelector := make(pubkeyFilter, 1)
	p, node := path.Split(key)
	for dir := strings.TrimRight(p, "/"); dir != node && dir != "" && dir != "/"; dir, _ = path.Split(p) {
		p = strings.TrimRight(dir, "/")
	}
	if p == "" || p == "/" {
		p = key
	}
	keySelector[0] = p

	data := flagset.Arg(1)
	if data == "" {
		flagset.Usage()
		os.Exit(1)
	}
	backendStore, err := getBackendStore(backendName, endpoint)
	if err != nil {
		log.Fatal(err)
	}
	d, err := ioutil.ReadFile(data)
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("setting consul node %q\n", nodeKey(key))
	if plaintext {
		err := setPlain(nodeKey(key), backendStore, d)
		if err != nil {
			log.Fatal(err)
			return
		}
		return
	}
	err = setEncrypted(nodeKey(key), keyring, d, backendStore, keySelector)
	if err != nil {
		log.Fatal(err)
	}
	return

}
func setPlain(key string, store backend.Store, d []byte) error {
	err := store.Set(key, d)
	return err

}

func setEncrypted(key, keyring string, d []byte, store backend.Store, keySelector pubkeyFilter) error {
	kr, err := os.Open(keyring)
	if err != nil {
		return err
	}
	defer kr.Close()
	secureValue, err := secconf.EncodeWith(d, kr, keySelector)
	if err != nil {
		return err
	}
	err = store.Set(key, secureValue)
	return err
}

func getBackendStore(provider string, endpoint string) (backend.Store, error) {
	if endpoint == "" {
		switch provider {
		case "consul":
			endpoint = "127.0.0.1:8500"
		case "etcd":
			endpoint = "http://127.0.0.1:4001"
		}
	}
	machines := []string{endpoint}
	switch provider {
	case "etcd":
		return etcd.New(machines)
	case "consul":
		return consul.New(machines)
	default:
		return nil, errors.New("invalid backend " + provider)
	}
}
