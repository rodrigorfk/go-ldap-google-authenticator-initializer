package main

import (
	"bufio"
	"crypto/tls"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"strconv"
	"strings"

	"github.com/joho/godotenv"
	ldap "gopkg.in/ldap.v2"
)

func main() {
	log.SetFlags(log.LstdFlags)
	log.SetPrefix("[LDAP-GOOGLE-AUTH] ")

	usernameParameter := flag.String("username", "", "username to bind to.")
	config := flag.String("config", "ldap-auth.conf", "LDAP auth config file.")
	flag.Parse()

	err := godotenv.Load(*config)
	if err != nil {
		log.Fatal("Error loading config file")
	}

	username := "empty"
	if os.Getenv("USERNAME_FROM") == "parameter" {
		username = *usernameParameter
	} else {
		username = os.Getenv(os.Getenv("USERNAME_FROM"))
	}

	if _, err := os.Stat(fmt.Sprintf("%s/%s/.google_authenticator", os.Getenv("USER_BASE_FOLDER"), username)); os.IsNotExist(err) {

		reader := bufio.NewReader(os.Stdin)
		password, _ := reader.ReadString('\n')
		password = strings.Replace(password, "\n", "", -1)

		l, err := ldap.Dial("tcp", fmt.Sprintf("%s:%s", os.Getenv("LDAP_HOST"), os.Getenv("LDAP_PORT")))
		if err != nil {
			log.Fatal("Error in dial: ", err)
		}
		defer l.Close()

		if ok, _ := strconv.ParseBool(os.Getenv("ENABLE_START_TLS")); ok {
			if err = l.StartTLS(&tls.Config{InsecureSkipVerify: true}); err != nil {
				log.Fatal("Error starting tls: ", err)
			}
		}

		fullusername := fmt.Sprintf("%s@%s", username, os.Getenv("BIND_DOMAIN"))
		if err = l.Bind(fullusername, password); err != nil {
			log.Fatal("Error binding: ", err)
		}

		sru, err := l.Search(ldap.NewSearchRequest(
			os.Getenv("USER_SEARCH_BASE"), ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
			fmt.Sprintf(os.Getenv("USER_SEARCH_FILTER"), username),
			[]string{os.Getenv("GOOGLE_AUTHORIZATION_ATTRIBUTE")},
			nil,
		))
		if err != nil {
			log.Fatal("Error searching: ", err)
		}

		if len(sru.Entries) != 1 {
			log.Fatal("too much user response")
		}

		for _, entry := range sru.Entries {
			googleAuthenticatorSecretKey := entry.GetAttributeValue(os.Getenv("GOOGLE_AUTHORIZATION_ATTRIBUTE"))
			if googleAuthenticatorSecretKey != "" {
				filename := fmt.Sprintf("%s/%s/.google_authenticator", os.Getenv("USER_BASE_FOLDER"), username)
				content := []byte(fmt.Sprintf(os.Getenv("GOOGLE_AUTHORIZATION_FILE_TEMPLATE"), googleAuthenticatorSecretKey))
				err := ioutil.WriteFile(filename, content, 0400)
				if err != nil {
					log.Fatal("Error writing file: ", err)
				}
				_, err = exec.Command("/usr/bin/chown", username, filename).Output()
				if err != nil {
					log.Fatal("Error changing file permissions: ", err)
				}
			}
		}
	}
}
