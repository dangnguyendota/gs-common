package common

import (
	"crypto"
	"crypto/md5"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/dangnguyendota/gs-interface"
	"github.com/dgrijalva/jwt-go"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"log"
	"net"
	"net/http"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// token contains user information
type UserTokenClaims struct {
	ExpiresAt int64
	User      gsi.User
}

func (u *UserTokenClaims) Valid() error {
	if u.ExpiresAt <= time.Now().UTC().Unix() {
		vErr := new(jwt.ValidationError)
		vErr.Inner = errors.New("token is expired")
		vErr.Errors |= jwt.ValidationErrorExpired
		return vErr
	}
	return nil
}

// token, parsed, valid
func ParseToken(tokenString string, secret string) (*UserTokenClaims, bool) {
	token, err := jwt.ParseWithClaims(tokenString, &UserTokenClaims{}, func(token *jwt.Token) (i interface{}, e error) {
		if s, ok := token.Method.(*jwt.SigningMethodHMAC); !ok || s.Hash != crypto.SHA256 {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(secret), nil
	})

	if err != nil {
		return nil, false
	}

	claims, ok := token.Claims.(*UserTokenClaims)
	if !ok || !token.Valid {
		return nil, false
	}

	return claims, true
}

func GenerateToken(user gsi.User, expiredTime int64, secret string) (string, error) {
	expiredAt := time.Now().UTC().Add(time.Duration(expiredTime) * time.Second).Unix()

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, &UserTokenClaims{
		User:      user,
		ExpiresAt: expiredAt,
	})
	tokenString, err := token.SignedString([]byte(secret))
	if err != nil {
		return "", errors.New("can not create token string")
	}

	return tokenString, nil
}

func GetIPAndPort(r *http.Request) (string, string) {
	var clientAddr string
	if ips := r.Header.Get("x-forwarded-for"); len(ips) > 0 {
		clientAddr = strings.Split(ips, ",")[0]
	} else {
		clientAddr = r.RemoteAddr
	}

	var clientIP, clientPort string
	if clientAddr != "" {
		clientAddr = strings.TrimSpace(clientAddr)
		if host, port, err := net.SplitHostPort(clientAddr); err == nil {
			clientIP = host
			clientPort = port
		} else if addrErr, ok := err.(*net.AddrError); ok {
			switch addrErr.Err {
			case "missing port in address":
				fallthrough
			case "too many colons in address":
				clientIP = clientAddr
			default:
			}
		}
	}

	return clientIP, clientPort
}

func NewLogger(folder, name string) *zap.Logger {
	encoderCfg := zapcore.EncoderConfig{
		MessageKey:     "msg",
		LevelKey:       "level",
		NameKey:        "logger",
		CallerKey:      "caller",
		EncodeLevel:    zapcore.LowercaseLevelEncoder,
		EncodeTime:     zapcore.ISO8601TimeEncoder,
		EncodeDuration: zapcore.StringDurationEncoder,
		EncodeCaller: func(caller zapcore.EntryCaller, encoder zapcore.PrimitiveArrayEncoder) {
			encoder.AppendString(name + ":" + time.Now().String() + ":" + caller.File + ":" + strconv.FormatInt(int64(caller.Line), 10))
		},
	}
	cfg := zap.NewProductionConfig()
	cfg.EncoderConfig = encoderCfg
	cfg.OutputPaths = []string{
		folder + "/" + name + ".log",
	}
	logger, err := cfg.Build(zap.AddCaller())

	if err != nil {
		log.Println(err)
	}
	return logger
}

func GetMD5Hash(text string) string {
	hasher := md5.New()
	hasher.Write([]byte(text))
	return hex.EncodeToString(hasher.Sum(nil))
}

func ExecuteCommand(name string, arg ...string) (string, error) {
	cmd := exec.Command(name, arg...)
	stdout, err := cmd.Output()
	if err != nil {
		return "", err
	}
	return string(stdout), nil
}
