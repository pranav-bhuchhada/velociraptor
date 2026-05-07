//go:build windows
// +build windows

package selfprotect

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
	config_proto "www.velocidex.com/golang/velociraptor/config/proto"
	"www.velocidex.com/golang/velociraptor/utils"
)

const (
	SERVICE_STOP          = 0x0020
	SERVICE_CHANGE_CONFIG = 0x0002
	WRITE_DAC             = 0x00040000
	WRITE_OWNER           = 0x00080000
	DELETE                = 0x00010000

	SE_SERVICE     = 0
	SE_FILE_OBJECT = 1

	DACL_SECURITY_INFORMATION           = 0x00000004
	PROTECTED_DACL_SECURITY_INFORMATION = 0x80000000

	NO_INHERITANCE = 0x0

	ACCESS_ALLOWED_ACE_TYPE = 0x0
	ACCESS_DENIED_ACE_TYPE  = 0x1

	ACL_REVISION = 2
)

var (
	modadvapi32 = windows.NewLazySystemDLL("advapi32.dll")

	procSetServiceObjectSecurity = modadvapi32.NewProc("SetServiceObjectSecurity")
	procQueryServiceObjectSecurity = modadvapi32.NewProc("QueryServiceObjectSecurity")
	procSetNamedSecurityInfoW    = modadvapi32.NewProc("SetNamedSecurityInfoW")
	procGetNamedSecurityInfoW    = modadvapi32.NewProc("GetNamedSecurityInfoW")
)

type ACL struct {
	AclRevision byte
	Sbz1        byte
	AclSize     uint16
	AceCount    uint16
	Sbz2        uint16
}

type ACCESS_ALLOWED_ACE struct {
	AceType  byte
	AceFlags byte
	AceSize  uint16
	Mask     uint32
	SidStart uint32
}

type SECURITY_DESCRIPTOR struct {
	Revision byte
	Sbz1     byte
	Control  uint16
	Owner    uintptr
	Group    uintptr
	Sacl     uintptr
	Dacl     uintptr
}

func GetProtectedPaths(config_obj *config_proto.Config) []string {
	if config_obj == nil || config_obj.Client == nil {
		return nil
	}

	var paths []string

	if config_obj.Client.WindowsInstaller != nil {
		installPath := utils.ExpandEnv(
			config_obj.Client.WindowsInstaller.InstallPath)
		if installPath != "" {
			paths = append(paths, installPath)

			configPath := strings.TrimSuffix(
				installPath, filepath.Ext(installPath)) + ".config.yaml"
			paths = append(paths, configPath)
		}
	}

	writebackPath := utils.ExpandEnv(config_obj.Client.WritebackWindows)
	if writebackPath != "" {
		paths = append(paths, writebackPath)
	}

	return paths
}

func getSystemSid() (*windows.SID, error) {
	return windows.CreateWellKnownSid(windows.WinLocalSystemSid)
}

func getAdministratorsSid() (*windows.SID, error) {
	return windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
}

func buildProtectiveACL() (*ACL, error) {
	systemSid, err := getSystemSid()
	if err != nil {
		return nil, fmt.Errorf("CreateWellKnownSid(SYSTEM): %w", err)
	}

	adminsSid, err := getAdministratorsSid()
	if err != nil {
		return nil, fmt.Errorf("CreateWellKnownSid(Administrators): %w", err)
	}

	systemSidLen := windows.GetLengthSid(systemSid)
	adminsSidLen := windows.GetLengthSid(adminsSid)

	allowAceSize := uint16(unsafe.Sizeof(ACCESS_ALLOWED_ACE{})) - 4 + uint16(systemSidLen)
	denyAceSize := uint16(unsafe.Sizeof(ACCESS_ALLOWED_ACE{})) - 4 + uint16(adminsSidLen)

	aclSize := uint16(unsafe.Sizeof(ACL{})) + allowAceSize + denyAceSize

	aclBuf := make([]byte, aclSize)
	acl := (*ACL)(unsafe.Pointer(&aclBuf[0]))
	acl.AclRevision = ACL_REVISION
	acl.AclSize = aclSize
	acl.AceCount = 2

	// Deny ACE first (deny ACEs should come before allow ACEs)
	denyAce := (*ACCESS_ALLOWED_ACE)(unsafe.Pointer(
		&aclBuf[unsafe.Sizeof(ACL{})]))
	denyAce.AceType = ACCESS_DENIED_ACE_TYPE
	denyAce.AceFlags = 0
	denyAce.AceSize = denyAceSize
	denyAce.Mask = uint32(SERVICE_STOP | SERVICE_CHANGE_CONFIG | DELETE | WRITE_DAC | WRITE_OWNER)
	copyMemory(
		unsafe.Pointer(&denyAce.SidStart),
		unsafe.Pointer(adminsSid),
		uintptr(adminsSidLen))

	// Allow ACE for SYSTEM
	allowOffset := unsafe.Sizeof(ACL{}) + uintptr(denyAceSize)
	allowAce := (*ACCESS_ALLOWED_ACE)(unsafe.Pointer(&aclBuf[allowOffset]))
	allowAce.AceType = ACCESS_ALLOWED_ACE_TYPE
	allowAce.AceFlags = 0
	allowAce.AceSize = allowAceSize
	allowAce.Mask = 0x000F01FF // SERVICE_ALL_ACCESS
	copyMemory(
		unsafe.Pointer(&allowAce.SidStart),
		unsafe.Pointer(systemSid),
		uintptr(systemSidLen))

	return acl, nil
}

func buildFileProtectiveACL() (*ACL, error) {
	systemSid, err := getSystemSid()
	if err != nil {
		return nil, fmt.Errorf("CreateWellKnownSid(SYSTEM): %w", err)
	}

	systemSidLen := windows.GetLengthSid(systemSid)
	allowAceSize := uint16(unsafe.Sizeof(ACCESS_ALLOWED_ACE{})) - 4 + uint16(systemSidLen)
	aclSize := uint16(unsafe.Sizeof(ACL{})) + allowAceSize

	aclBuf := make([]byte, aclSize)
	acl := (*ACL)(unsafe.Pointer(&aclBuf[0]))
	acl.AclRevision = ACL_REVISION
	acl.AclSize = aclSize
	acl.AceCount = 1

	// Allow ACE for SYSTEM only (GENERIC_ALL equivalent for files)
	allowAce := (*ACCESS_ALLOWED_ACE)(unsafe.Pointer(
		&aclBuf[unsafe.Sizeof(ACL{})]))
	allowAce.AceType = ACCESS_ALLOWED_ACE_TYPE
	allowAce.AceFlags = 0
	allowAce.AceSize = allowAceSize
	allowAce.Mask = 0x1F01FF // FILE_ALL_ACCESS
	copyMemory(
		unsafe.Pointer(&allowAce.SidStart),
		unsafe.Pointer(systemSid),
		uintptr(systemSidLen))

	return acl, nil
}

func copyMemory(dst, src unsafe.Pointer, size uintptr) {
	dstSlice := unsafe.Slice((*byte)(dst), size)
	srcSlice := unsafe.Slice((*byte)(src), size)
	copy(dstSlice, srcSlice)
}

func ApplyServiceProtection(serviceName string) error {
	scm, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT)
	if err != nil {
		return fmt.Errorf("OpenSCManager: %w", err)
	}
	defer windows.CloseServiceHandle(scm)

	serviceNamePtr, err := windows.UTF16PtrFromString(serviceName)
	if err != nil {
		return fmt.Errorf("UTF16PtrFromString: %w", err)
	}

	svc, err := windows.OpenService(scm, serviceNamePtr,
		windows.READ_CONTROL|WRITE_DAC)
	if err != nil {
		return fmt.Errorf("OpenService(%s): %w", serviceName, err)
	}
	defer windows.CloseServiceHandle(svc)

	acl, err := buildProtectiveACL()
	if err != nil {
		return fmt.Errorf("buildProtectiveACL: %w", err)
	}

	r1, _, e1 := procSetServiceObjectSecurity.Call(
		uintptr(svc),
		uintptr(DACL_SECURITY_INFORMATION|PROTECTED_DACL_SECURITY_INFORMATION),
		uintptr(unsafe.Pointer(buildSecurityDescriptorWithDACL(acl))))
	if r1 == 0 {
		return fmt.Errorf("SetServiceObjectSecurity: %w", e1)
	}

	return nil
}

func buildSecurityDescriptorWithDACL(acl *ACL) *SECURITY_DESCRIPTOR {
	sd := &SECURITY_DESCRIPTOR{}
	sd.Revision = 1
	// SE_DACL_PRESENT | SE_SELF_RELATIVE is not set (absolute format)
	sd.Control = 0x0004 // SE_DACL_PRESENT
	sd.Dacl = uintptr(unsafe.Pointer(acl))
	return sd
}

func RemoveServiceProtection(serviceName string) error {
	scm, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT)
	if err != nil {
		return fmt.Errorf("OpenSCManager: %w", err)
	}
	defer windows.CloseServiceHandle(scm)

	serviceNamePtr, err := windows.UTF16PtrFromString(serviceName)
	if err != nil {
		return fmt.Errorf("UTF16PtrFromString: %w", err)
	}

	svc, err := windows.OpenService(scm, serviceNamePtr,
		windows.READ_CONTROL|WRITE_DAC)
	if err != nil {
		return fmt.Errorf("OpenService(%s): %w", serviceName, err)
	}
	defer windows.CloseServiceHandle(svc)

	// Build a permissive DACL that allows everyone default access
	systemSid, err := getSystemSid()
	if err != nil {
		return err
	}
	adminsSid, err := getAdministratorsSid()
	if err != nil {
		return err
	}

	systemSidLen := windows.GetLengthSid(systemSid)
	adminsSidLen := windows.GetLengthSid(adminsSid)

	// Two allow ACEs: SYSTEM full control, Administrators full control
	allowAce1Size := uint16(unsafe.Sizeof(ACCESS_ALLOWED_ACE{})) - 4 + uint16(systemSidLen)
	allowAce2Size := uint16(unsafe.Sizeof(ACCESS_ALLOWED_ACE{})) - 4 + uint16(adminsSidLen)
	aclSize := uint16(unsafe.Sizeof(ACL{})) + allowAce1Size + allowAce2Size

	aclBuf := make([]byte, aclSize)
	acl := (*ACL)(unsafe.Pointer(&aclBuf[0]))
	acl.AclRevision = ACL_REVISION
	acl.AclSize = aclSize
	acl.AceCount = 2

	// SYSTEM full control
	ace1 := (*ACCESS_ALLOWED_ACE)(unsafe.Pointer(&aclBuf[unsafe.Sizeof(ACL{})]))
	ace1.AceType = ACCESS_ALLOWED_ACE_TYPE
	ace1.AceFlags = 0
	ace1.AceSize = allowAce1Size
	ace1.Mask = 0x000F01FF // SERVICE_ALL_ACCESS
	copyMemory(unsafe.Pointer(&ace1.SidStart), unsafe.Pointer(systemSid), uintptr(systemSidLen))

	// Administrators full control
	ace2Offset := unsafe.Sizeof(ACL{}) + uintptr(allowAce1Size)
	ace2 := (*ACCESS_ALLOWED_ACE)(unsafe.Pointer(&aclBuf[ace2Offset]))
	ace2.AceType = ACCESS_ALLOWED_ACE_TYPE
	ace2.AceFlags = 0
	ace2.AceSize = allowAce2Size
	ace2.Mask = 0x000F01FF // SERVICE_ALL_ACCESS
	copyMemory(unsafe.Pointer(&ace2.SidStart), unsafe.Pointer(adminsSid), uintptr(adminsSidLen))

	r1, _, e1 := procSetServiceObjectSecurity.Call(
		uintptr(svc),
		uintptr(DACL_SECURITY_INFORMATION),
		uintptr(unsafe.Pointer(buildSecurityDescriptorWithDACL(acl))))
	if r1 == 0 {
		return fmt.Errorf("SetServiceObjectSecurity: %w", e1)
	}

	return nil
}

func ApplyFileProtection(paths []string) error {
	acl, err := buildFileProtectiveACL()
	if err != nil {
		return fmt.Errorf("buildFileProtectiveACL: %w", err)
	}

	var lastErr error
	for _, path := range paths {
		if _, err := os.Stat(path); os.IsNotExist(err) {
			continue
		}

		pathPtr, err := windows.UTF16PtrFromString(path)
		if err != nil {
			lastErr = err
			continue
		}

		r1, _, e1 := procSetNamedSecurityInfoW.Call(
			uintptr(unsafe.Pointer(pathPtr)),
			uintptr(SE_FILE_OBJECT),
			uintptr(DACL_SECURITY_INFORMATION|PROTECTED_DACL_SECURITY_INFORMATION),
			0, // owner
			0, // group
			uintptr(unsafe.Pointer(acl)),
			0) // sacl
		if r1 != 0 {
			lastErr = fmt.Errorf("SetNamedSecurityInfo(%s): %w", path, e1)
		}
	}
	return lastErr
}

func RemoveFileProtection(paths []string) error {
	systemSid, err := getSystemSid()
	if err != nil {
		return err
	}
	adminsSid, err := getAdministratorsSid()
	if err != nil {
		return err
	}

	systemSidLen := windows.GetLengthSid(systemSid)
	adminsSidLen := windows.GetLengthSid(adminsSid)

	// Build ACL with SYSTEM and Administrators full access
	ace1Size := uint16(unsafe.Sizeof(ACCESS_ALLOWED_ACE{})) - 4 + uint16(systemSidLen)
	ace2Size := uint16(unsafe.Sizeof(ACCESS_ALLOWED_ACE{})) - 4 + uint16(adminsSidLen)
	aclSize := uint16(unsafe.Sizeof(ACL{})) + ace1Size + ace2Size

	aclBuf := make([]byte, aclSize)
	acl := (*ACL)(unsafe.Pointer(&aclBuf[0]))
	acl.AclRevision = ACL_REVISION
	acl.AclSize = aclSize
	acl.AceCount = 2

	ace1 := (*ACCESS_ALLOWED_ACE)(unsafe.Pointer(&aclBuf[unsafe.Sizeof(ACL{})]))
	ace1.AceType = ACCESS_ALLOWED_ACE_TYPE
	ace1.AceFlags = 0
	ace1.AceSize = ace1Size
	ace1.Mask = 0x1F01FF // FILE_ALL_ACCESS
	copyMemory(unsafe.Pointer(&ace1.SidStart), unsafe.Pointer(systemSid), uintptr(systemSidLen))

	ace2Offset := unsafe.Sizeof(ACL{}) + uintptr(ace1Size)
	ace2 := (*ACCESS_ALLOWED_ACE)(unsafe.Pointer(&aclBuf[ace2Offset]))
	ace2.AceType = ACCESS_ALLOWED_ACE_TYPE
	ace2.AceFlags = 0
	ace2.AceSize = ace2Size
	ace2.Mask = 0x1F01FF // FILE_ALL_ACCESS
	copyMemory(unsafe.Pointer(&ace2.SidStart), unsafe.Pointer(adminsSid), uintptr(adminsSidLen))

	var lastErr error
	for _, path := range paths {
		if _, err := os.Stat(path); os.IsNotExist(err) {
			continue
		}

		pathPtr, err := windows.UTF16PtrFromString(path)
		if err != nil {
			lastErr = err
			continue
		}

		// Remove the protected DACL flag and set permissive ACL
		r1, _, e1 := procSetNamedSecurityInfoW.Call(
			uintptr(unsafe.Pointer(pathPtr)),
			uintptr(SE_FILE_OBJECT),
			uintptr(DACL_SECURITY_INFORMATION),
			0, 0,
			uintptr(unsafe.Pointer(acl)),
			0)
		if r1 != 0 {
			lastErr = fmt.Errorf("SetNamedSecurityInfo(%s): %w", path, e1)
		}
	}
	return lastErr
}

func VerifyServiceProtection(serviceName string) (bool, error) {
	scm, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT)
	if err != nil {
		return false, fmt.Errorf("OpenSCManager: %w", err)
	}
	defer windows.CloseServiceHandle(scm)

	serviceNamePtr, err := windows.UTF16PtrFromString(serviceName)
	if err != nil {
		return false, err
	}

	svc, err := windows.OpenService(scm, serviceNamePtr, windows.READ_CONTROL)
	if err != nil {
		return false, fmt.Errorf("OpenService(%s): %w", serviceName, err)
	}
	defer windows.CloseServiceHandle(svc)

	// Query the security descriptor size
	var needed uint32
	procQueryServiceObjectSecurity.Call(
		uintptr(svc),
		uintptr(DACL_SECURITY_INFORMATION),
		0,
		0,
		uintptr(unsafe.Pointer(&needed)))

	if needed == 0 {
		return false, fmt.Errorf("QueryServiceObjectSecurity returned 0 needed bytes")
	}

	buf := make([]byte, needed)
	r1, _, e1 := procQueryServiceObjectSecurity.Call(
		uintptr(svc),
		uintptr(DACL_SECURITY_INFORMATION),
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(needed),
		uintptr(unsafe.Pointer(&needed)))
	if r1 == 0 {
		return false, fmt.Errorf("QueryServiceObjectSecurity: %w", e1)
	}

	// Check that we have a deny ACE for administrators in the DACL
	return hasDenyAceForAdministrators(buf), nil
}

func VerifyFileProtection(paths []string) ([]string, error) {
	var tampered []string

	for _, path := range paths {
		if _, err := os.Stat(path); os.IsNotExist(err) {
			continue
		}

		if !verifyFileACL(path) {
			tampered = append(tampered, path)
		}
	}

	return tampered, nil
}

func verifyFileACL(path string) bool {
	sd, err := windows.GetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION)
	if err != nil || sd == nil {
		return false
	}

	dacl, _, err := sd.DACL()
	if err != nil || dacl == nil {
		return false
	}

	// A properly protected file has exactly 1 ACE (SYSTEM full control)
	return dacl.AceCount == 1
}

func hasDenyAceForAdministrators(sdBuf []byte) bool {
	// Parse the self-relative security descriptor to find the DACL
	if len(sdBuf) < 20 {
		return false
	}

	// In a self-relative SD, the DACL offset is at bytes 16-19
	daclOffset := *(*uint32)(unsafe.Pointer(&sdBuf[16]))
	if daclOffset == 0 || int(daclOffset) >= len(sdBuf) {
		return false
	}

	aclHeader := (*ACL)(unsafe.Pointer(&sdBuf[daclOffset]))
	if aclHeader.AceCount == 0 {
		return false
	}

	// Walk ACEs looking for a deny ACE
	offset := daclOffset + uint32(unsafe.Sizeof(ACL{}))
	for i := uint16(0); i < aclHeader.AceCount; i++ {
		if int(offset)+4 > len(sdBuf) {
			break
		}
		ace := (*ACCESS_ALLOWED_ACE)(unsafe.Pointer(&sdBuf[offset]))
		if ace.AceType == ACCESS_DENIED_ACE_TYPE {
			return true
		}
		offset += uint32(ace.AceSize)
	}

	return false
}
