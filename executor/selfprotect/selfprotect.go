//go:build !windows
// +build !windows

package selfprotect

import (
	config_proto "www.velocidex.com/golang/velociraptor/config/proto"
)

func GetProtectedPaths(config_obj *config_proto.Config) []string {
	return nil
}

func ApplyServiceProtection(serviceName string) error {
	return nil
}

func RemoveServiceProtection(serviceName string) error {
	return nil
}

func ApplyFileProtection(paths []string) error {
	return nil
}

func RemoveFileProtection(paths []string) error {
	return nil
}

func VerifyServiceProtection(serviceName string) (bool, error) {
	return true, nil
}

func VerifyFileProtection(paths []string) ([]string, error) {
	return nil, nil
}
