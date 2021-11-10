package gosoap

import (
	"encoding/xml"
	"time"
	"encoding/base64"
	"crypto/sha1"
	"github.com/elgs/gostrgen"
	"fmt"
)

/*************************
	WS-Security types
*************************/
const (
	passwordType = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordDigest"
	encodingType = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary"
)
//XMLName xml.Name `xml:"http://purl.org/rss/1.0/modules/content/ encoded"`
type security struct {
	//XMLName xml.Name  `xml:"wsse:Security"`
	XMLName xml.Name `xml:"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd Security"`
	Auth wsAuth
}

type password struct {
	//XMLName xml.Name `xml:"wsse:Password"`
	Type string `xml:"Type,attr"`
	Password string `xml:",chardata"`
}

type nonce struct {
	//XMLName xml.Name `xml:"wsse:Nonce"`
	Type string `xml:"EncodingType,attr"`
	Nonce string `xml:",chardata"`
}

type wsAuth struct {
	XMLName xml.Name  `xml:"UsernameToken"`
	Username string   `xml:"Username"`
	Password password `xml:"Password"`
	Nonce nonce      `xml:"Nonce"`
	Created string    `xml:"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd Created"`
}
/*
        <Security s:mustUnderstand="1" xmlns="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">
            <UsernameToken>
                <Username>admin</Username>
                <Password Type="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordDigest">edBuG+qVavQKLoWuGWQdPab4IBE=</Password>
                <Nonce EncodingType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary">S7wO1ZFTh0KXv2CR7bd2ZXkLAAAAAA==</Nonce>
                <Created xmlns="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">2018-04-10T18:04:25.836Z</Created>
            </UsernameToken>
        </Security>
 */

func NewSecurity(username, passwd string) security {
	/** Generating Nonce sequence **/
	charsToGenerate := 32
	charSet := gostrgen.Lower | gostrgen.Digit

	nonceSeq, _ := gostrgen.RandGen(charsToGenerate, charSet, "", "")
	fmt.Println("nonceSeq: ",string(nonceSeq))
	nonceSeq = "81jcwjjjiubjy0ugi6zus6dw9zk3ho0p";
	dt, _ := time.Parse("2016-01-02 15:04:05", "2018-04-23 12:24:51")
	fmt.Println("dt: ",dt)
	auth := security{
		Auth:wsAuth{
			Username:username,
			Password:password {
				Type:passwordType,
				// Password:generateToken(username, nonceSeq, time.Now().UTC(), passwd),
				Password:generateToken(username, nonceSeq, dt, passwd),
			},
			Nonce:nonce {
				Type:encodingType,
				Nonce: nonceSeq,
			},
			// Created: time.Now().UTC().Format(time.RFC3339Nano),
			Created: dt.Format(time.RFC3339Nano),
		},
	}

	return auth
}

//Digest = B64ENCODE( SHA1( B64DECODE( Nonce ) + Date + Password ) )
func generateToken(Username string, Nonce string, Created time.Time, Password string) string {

	sDec, _ := base64.StdEncoding.DecodeString(Nonce)
	fmt.Println("Nonce: ",Nonce,", sDec",sDec)

	hasher := sha1.New()
	//hasher.Write([]byte((base64.StdEncoding.EncodeToString([]byte(Nonce)) + Created.Format(time.RFC3339) + Password)))
	res,err := hasher.Write([]byte(string(sDec) + Created.Format(time.RFC3339Nano) + Password))
	fmt.Println("Password: ",Password,", res: ",res,", err: ",err)
	return base64.StdEncoding.EncodeToString(hasher.Sum(nil))
}

