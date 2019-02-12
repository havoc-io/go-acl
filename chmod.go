package acl

import (
	"os"

	"golang.org/x/sys/windows"
)

var creatorOwnerSid, creatorGroupSid, everyoneSid *windows.SID

func init() {
	// Create the CREATOR OWNER well-known SID.
	if s, err := windows.StringToSid("S-1-3-0"); err != nil {
		panic("unable to create CREATOR OWNER well-known SID")
	} else {
		creatorOwnerSid = s
	}

	// Create the CREATOR GROUP well-known SID.
	if s, err := windows.StringToSid("S-1-3-1"); err != nil {
		panic("unable to create CREATOR GROUP well-known SID")
	} else {
		creatorGroupSid = s
	}

	// Create the EVERYONE well-known SID.
	if s, err := windows.StringToSid("S-1-1-0"); err != nil {
		panic("unable to create EVERYONE well-known SID")
	} else {
		everyoneSid = s
	}
}

// Change the permissions of the specified file. Only the nine
// least-significant bytes are used, allowing access by the file's owner, the
// file's group, and everyone else to be explicitly controlled.
func Chmod(name string, mode os.FileMode) error {
	return Apply(
		name,
		true,
		false,
		GrantSid((uint32(mode)&0700)<<23, creatorOwnerSid),
		GrantSid((uint32(mode)&0070)<<26, creatorGroupSid),
		GrantSid((uint32(mode)&0007)<<29, everyoneSid),
	)
}
