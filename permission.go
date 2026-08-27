package identity

import (
	"sync"

	"github.com/gobwas/glob"
	pb "github.com/kodeart/identity-sdk-go/proto/identity/v1"
)

var compileCache sync.Map // pattern(string) -> glob.Glob

// Can reports whether the SessionUser holds perm, checking it against every
// resolved permission glob in SessionUser.Permissions. "*" matches anything,
// "task.*" matches one sub-token, an exact string matches only itself.
//
// SessionUser.Permissions is the authoritative, resolved effective set
// (roles + grants - exclusions); this is the enforcement point.
func Can(u *pb.SessionUser, perm string) bool {
	if u == nil {
		return false
	}
	for _, p := range u.GetPermissions() {
		if matches(p, perm) {
			return true
		}
	}
	return false
}

func compile(pattern string) (glob.Glob, bool) {
	if cached, ok := compileCache.Load(pattern); ok {
		return cached.(glob.Glob), true
	}
	g, err := glob.Compile(pattern, '.')
	if err != nil {
		return nil, false
	}
	compileCache.Store(pattern, g)
	return g, true
}

func matches(pattern, perm string) bool {
	if pattern == "*" {
		return true
	}
	g, ok := compile(pattern)
	if !ok {
		return false
	}
	return g.Match(perm)
}
