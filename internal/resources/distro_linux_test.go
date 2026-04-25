//go:build linux

package resources

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDetectDistroFamily(t *testing.T) {
	tests := []struct {
		name        string
		osRelease   string
		wantFamily  DistroFamily
		wantAnchor  string
		wantPretty  string
	}{
		{
			name: "ubuntu",
			osRelease: `NAME="Ubuntu"
ID=ubuntu
ID_LIKE=debian
PRETTY_NAME="Ubuntu 24.04 LTS"
`,
			wantFamily: DistroDebian,
			wantAnchor: "/usr/local/share/ca-certificates",
			wantPretty: "Ubuntu 24.04 LTS",
		},
		{
			name: "debian",
			osRelease: `ID=debian
PRETTY_NAME="Debian GNU/Linux 12 (bookworm)"
`,
			wantFamily: DistroDebian,
			wantAnchor: "/usr/local/share/ca-certificates",
		},
		{
			name: "linux mint inherits debian via ID_LIKE chain",
			osRelease: `ID=linuxmint
ID_LIKE="ubuntu debian"
`,
			wantFamily: DistroDebian,
			wantAnchor: "/usr/local/share/ca-certificates",
		},
		{
			name: "fedora",
			osRelease: `ID=fedora
PRETTY_NAME="Fedora Linux 41 (Workstation Edition)"
`,
			wantFamily: DistroRHEL,
			wantAnchor: "/etc/pki/ca-trust/source/anchors",
		},
		{
			name: "rocky inherits rhel via ID_LIKE",
			osRelease: `ID=rocky
ID_LIKE="rhel centos fedora"
`,
			wantFamily: DistroRHEL,
			wantAnchor: "/etc/pki/ca-trust/source/anchors",
		},
		{
			name: "amazon linux 2",
			osRelease: `ID=amzn
ID_LIKE=fedora
`,
			wantFamily: DistroRHEL,
			wantAnchor: "/etc/pki/ca-trust/source/anchors",
		},
		{
			name: "arch",
			osRelease: `ID=arch
`,
			wantFamily: DistroArch,
			wantAnchor: "/etc/ca-certificates/trust-source/anchors",
		},
		{
			name: "manjaro inherits arch via ID_LIKE",
			osRelease: `ID=manjaro
ID_LIKE=arch
`,
			wantFamily: DistroArch,
			wantAnchor: "/etc/ca-certificates/trust-source/anchors",
		},
		{
			name: "opensuse leap",
			osRelease: `ID="opensuse-leap"
ID_LIKE="suse opensuse"
`,
			wantFamily: DistroSUSE,
			wantAnchor: "/etc/pki/trust/anchors",
		},
		{
			name: "alpine",
			osRelease: `ID=alpine
`,
			wantFamily: DistroAlpine,
			wantAnchor: "/usr/local/share/ca-certificates",
		},
		{
			name: "unknown distro with no matching ID_LIKE",
			osRelease: `ID=mystery
ID_LIKE=
`,
			wantFamily: DistroUnknown,
			wantAnchor: "",
		},
		{
			name:       "empty file → unknown",
			osRelease:  "",
			wantFamily: DistroUnknown,
			wantAnchor: "",
		},
		{
			name: "comments and blank lines are ignored",
			osRelease: `# this is a comment

ID=fedora

# trailing comment
`,
			wantFamily: DistroRHEL,
			wantAnchor: "/etc/pki/ca-trust/source/anchors",
		},
		{
			name: "single-quoted values are stripped",
			osRelease: `ID='ubuntu'
PRETTY_NAME='Ubuntu Server'
`,
			wantFamily: DistroDebian,
			wantAnchor: "/usr/local/share/ca-certificates",
			wantPretty: "Ubuntu Server",
		},
		{
			name: "lines without = are skipped",
			osRelease: `not a valid line
ID=arch
also not valid
`,
			wantFamily: DistroArch,
			wantAnchor: "/etc/ca-certificates/trust-source/anchors",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "os-release")
			require.NoError(t, os.WriteFile(path, []byte(tc.osRelease), 0o644))
			info, err := detectDistroFamilyAt(path)
			require.NoError(t, err)
			assert.Equal(t, tc.wantFamily, info.Family)
			assert.Equal(t, tc.wantAnchor, info.AnchorDir)
			if tc.wantPretty != "" {
				assert.Equal(t, tc.wantPretty, info.Name)
			}
		})
	}
}

func TestDetectDistroFamily_MissingFile(t *testing.T) {
	info, err := detectDistroFamilyAt(filepath.Join(t.TempDir(), "no-such-file"))
	require.NoError(t, err, "missing /etc/os-release should not be an error")
	assert.Equal(t, DistroUnknown, info.Family)
	assert.Empty(t, info.AnchorDir)
}

func TestParseOSRelease_StripsQuotes(t *testing.T) {
	id, idLike, pretty, err := parseOSRelease(strings.NewReader(`ID="ubuntu"
ID_LIKE="debian"
PRETTY_NAME="Ubuntu 24.04"
`))
	require.NoError(t, err)
	assert.Equal(t, "ubuntu", id)
	assert.Equal(t, "debian", idLike)
	assert.Equal(t, "Ubuntu 24.04", pretty)
}

func TestClassify_PreferIDOverIDLike(t *testing.T) {
	// When ID is recognized, ID_LIKE is irrelevant.
	assert.Equal(t, DistroDebian, classify("ubuntu", "rhel"))
	assert.Equal(t, DistroRHEL, classify("fedora", "debian"))
}

func TestClassify_FirstMatchingIDLikeWins(t *testing.T) {
	// ID is unknown, walk ID_LIKE in order until something matches.
	assert.Equal(t, DistroDebian, classify("mystery", "ubuntu debian"))
	assert.Equal(t, DistroDebian, classify("mystery", "debian rhel"))
	assert.Equal(t, DistroRHEL, classify("mystery", "fedora debian"))
}
