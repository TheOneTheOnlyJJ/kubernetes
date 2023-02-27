//go:build windows
// +build windows

/*
Copyright 2019 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package mounttest

import (
	"fmt"
	"os"
	osuser "os/user"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	// https://docs.microsoft.com/en-us/windows/win32/fileio/file-access-rights-constants
	// read = read data | read attributes
	READ_PERMISSIONS = 0x0001 | 0x0080

	// write = write data | append data | write attributes | write EA
	WRITE_PERMISSIONS = 0x0002 | 0x0004 | 0x0100 | 0x0010

	// execute = read data | file execute
	EXECUTE_PERMISSIONS = 0x0001 | 0x0020

	// Accounts
	EVERYONE = "Everyone"
	USERS    = "Users"
	NONE     = "None"

	// Well-known SID Strings
	// https://support.microsoft.com/en-us/help/243330/well-known-security-identifiers-in-windows-operating-systems
	CREATOR_SID_STR  = "S-1-3-0"
	GROUP_SID_STR    = "S-1-3-1"
	EVERYONE_SID_STR = "S-1-1-0"

	// Constants for AceType
	// https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-ace_header
	ACCESS_ALLOWED_ACE_TYPE = 0
	ACCESS_DENIED_ACE_TYPE  = 1

	// Values that specify the type of a security identifier (SID)
	// https://learn.microsoft.com/en-us/windows/win32/api/winnt/ne-winnt-sid_name_use
	SidTypeUser           = 1
	SidTypeGroup          = 2
	SidTypeDomain         = 3
	SidTypeAlias          = 4
	SidTypeWellKnownGroup = 5
	SidTypeDeletedAccount = 6
	SidTypeInvalid        = 7
	SidTypeUnknown        = 8
	SidTypeComputer       = 9
	SidTypeLabel          = 10
	SidTypeLogonSession   = 11
)

var (
	advapi32                  = windows.MustLoadDLL("advapi32.dll")
	procSetEntriesInAclW      = advapi32.MustFindProc("SetEntriesInAclW")
	procGetAce                = advapi32.MustFindProc("GetAce")
	procGetNamedSecurityInfoW = advapi32.MustFindProc("GetNamedSecurityInfoW")
)

// https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-acl
type ACL struct {
	aclRevision byte
	sbz1        byte
	aclSize     uint16
	aceCount    uint16
	sbz2        uint16
}

// https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-access_allowed_ace
type accessAllowedAce struct {
	aceType  byte
	aceFlags byte
	aceSize  uint16
	mask     windows.ACCESS_MASK
	sid      windows.SID
}

func umask(mask int) int {
	// noop for Windows.
	return 0
}

func fsType(path string) error {
	// only NTFS is supported at the moment.
	return nil
}

func fileOwner(path string) error {
	// Windows does not have owner UID / GID. However, it has owner SID.
	// not currently implemented in Kubernetes, so noop.
	return nil
}

func fileMode(path string) error {
	if path == "" {
		return nil
	}

	fMode, err := getFileMode(path)
	if err != nil {
		return err
	}

	fmt.Printf("mode of Windows file %q: %v\n", path, fMode)
	return nil
}

func filePerm(path string) error {
	if path == "" {
		return nil
	}

	fMode, err := getFileMode(path)
	if err != nil {
		return err
	}
	fPerm := fMode.Perm()

	fmt.Printf("perms of Windows file %q: %v\n", path, fPerm)
	return nil
}

func getFileMode(path string) (os.FileMode, error) {
	var (
		daclHandle, secDesc windows.Handle
		owner, group        *windows.SID
	)
	err := getNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.GROUP_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION|windows.UNPROTECTED_DACL_SECURITY_INFORMATION,
		&owner,
		&group,
		&daclHandle,
		nil,
		&secDesc,
	)
	if err != nil {
		return 0, err
	}

	fmt.Printf("Owner SID = %s\nGroup SID = %s\n", owner.String(), group.String())
	ownerAccountName, _, ownerAccountType, err := owner.LookupAccount("")
	if err != nil {
		return 0, err
	}
	if ownerAccountName == "" {
		ownerAccountName = NONE
	}
	groupAccountName, _, groupAccountType, err := group.LookupAccount("")
	if err != nil {
		return 0, err
	}
	if groupAccountName == "" {
		groupAccountName = NONE
	}
	fmt.Printf("Owner Account Name = %s\nOwner Account Type = %d\nGroup Account Name = %s\nGroup Account Type = %d\n", ownerAccountName, ownerAccountType, groupAccountName, groupAccountType)

	fmt.Printf("Checking ownerAccountType\n")
	// If owner account is of user type we have to get the groups which the owner is a member of
	ownerGroupSids := []*windows.SID{}
	if ownerAccountType == SidTypeUser {
		fmt.Printf("ownerAccountType is user\n")
		fmt.Printf("Before Lookup\n")
		user, err := osuser.Lookup(ownerAccountName)
		if err != nil {
			fmt.Printf("%v\n", err)
			return 0, err
		}
		fmt.Printf("After Lookup\n")
		fmt.Printf("Before GroupIds\n")
		ownerGroupSidsStrings, err := user.GroupIds()
		if err != nil {
			fmt.Printf("%v\n", err)
			return 0, err
		}
		for _, ownerGroupSidString := range ownerGroupSidsStrings {
			ownerGroupSid, err := windows.StringToSid(ownerGroupSidString)
			if err != nil {
				return 0, err
			}
			ownerGroupSids = append(ownerGroupSids, ownerGroupSid)
		}
		fmt.Printf("After GroupIds\n")

		fmt.Printf("------------------------------------\n")
		for _, usid := range ownerGroupSids {
			fmt.Printf("%s\n", usid.String())
		}
		fmt.Printf("------------------------------------\n")
	} else if ownerAccountType != SidTypeGroup && ownerAccountType != SidTypeWellKnownGroup && ownerAccountType != SidTypeAlias {
		fmt.Printf("ownerAccountType is NOT user NOR group\n")
	}

	defer windows.LocalFree(secDesc)

	dacl := (*ACL)(unsafe.Pointer(daclHandle))
	aces, err := getACEs(dacl)
	if err != nil {
		return 0, err
	}

	allowMode := 0
	denyMode := 0
	fmt.Printf("----- Enter for loop -----\n")
	for _, ace := range aces {
		fmt.Printf("\nRead ACE SID = %s\n", ace.sid.String())
		accountName, _, _, err := ace.sid.LookupAccount("")
		if err != nil {
			return 0, err
		}

		// LookupAccount may return an empty string.
		if accountName == "" {
			accountName = NONE
		}
		fmt.Printf("Account Name = %s\n", accountName)

		perms := 0
		if (ace.mask & READ_PERMISSIONS) == READ_PERMISSIONS {
			perms = 0x4
		}
		if (ace.mask & WRITE_PERMISSIONS) == WRITE_PERMISSIONS {
			perms |= 0x2
		}
		if (ace.mask & EXECUTE_PERMISSIONS) == EXECUTE_PERMISSIONS {
			perms |= 0x1
		}

		mode := 0
		if owner.Equals(&ace.sid) {
			mode = perms << 6
			fmt.Printf("Owner SID matched!\n")
		}
		if group.Equals(&ace.sid) || ownerAccountType == SidTypeAlias || ownerAccountType == SidTypeGroup || ownerAccountType == SidTypeWellKnownGroup {
			mode |= perms << 3
			fmt.Printf("Group SID matched!\n")
		} else {
			for _, usid := range ownerGroupSids {
				fmt.Printf("usid = %s\nace sid = %s\n", usid.String(), ace.sid.String())
				if usid.Equals(&ace.sid) {
					mode |= perms << 3
				}
			}
		}
		if accountName == EVERYONE || accountName == USERS {
			mode |= perms
			fmt.Printf("Others SID matched!\n")
		}

		if ace.aceType == ACCESS_ALLOWED_ACE_TYPE {
			allowMode |= mode
		} else if ace.aceType == ACCESS_DENIED_ACE_TYPE {
			denyMode |= mode
		}
		fmt.Printf("Perms = %d\nMode = %d\n", perms, mode)
	}
	fmt.Printf("----- Exit for loop -----\n")

	// Exclude the denied permissions.
	return os.FileMode(allowMode & ^denyMode), nil
}

// https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-getace
func getACEs(acl *ACL) ([]*accessAllowedAce, error) {
	aces := make([]*accessAllowedAce, acl.aceCount)
	var ace *accessAllowedAce

	for i := uint16(0); i < acl.aceCount; i++ {
		ret, _, _ := procGetAce.Call(
			uintptr(unsafe.Pointer(acl)),
			uintptr(i),
			uintptr(unsafe.Pointer(&ace)),
		)
		if ret == 0 {
			return []*accessAllowedAce{}, windows.GetLastError()
		}

		aceBytes := make([]byte, ace.aceSize)
		copy(aceBytes, (*[(1 << 31) - 1]byte)(unsafe.Pointer(ace))[:len(aceBytes)])
		aces[i] = (*accessAllowedAce)(unsafe.Pointer(&aceBytes[0]))
	}

	return aces, nil
}

// https://docs.microsoft.com/en-us/windows/win32/api/aclapi/nf-aclapi-getnamedsecurityinfow
func getNamedSecurityInfo(objectName string, objectType windows.SE_OBJECT_TYPE, secInfo windows.SECURITY_INFORMATION, owner, group **windows.SID, dacl, sacl, secDesc *windows.Handle) error {
	ret, _, _ := procGetNamedSecurityInfoW.Call(
		uintptr(unsafe.Pointer(windows.StringToUTF16Ptr(objectName))),
		uintptr(objectType),
		uintptr(secInfo),
		uintptr(unsafe.Pointer(owner)),
		uintptr(unsafe.Pointer(group)),
		uintptr(unsafe.Pointer(dacl)),
		uintptr(unsafe.Pointer(sacl)),
		uintptr(unsafe.Pointer(secDesc)),
	)
	if ret != 0 {
		return windows.Errno(ret)
	}
	return nil
}
