package identity

import (
	"testing"

	pb "github.com/kodeart/identity-sdk-go/proto/identity/v1"
)

func TestCan(t *testing.T) {
	u := &pb.SessionUser{
		Permissions: []string{"task.*", "report.view"},
	}
	cases := []struct {
		perm string
		want bool
	}{
		{"task.create", true},
		{"report.view", true},
		{"report.delete", false},
		{"task.sub.view", false},
		{"unrelated", false},
	}
	for _, c := range cases {
		if got := Can(u, c.perm); got != c.want {
			t.Errorf("Can(%q) = %v, want %v", c.perm, got, c.want)
		}
	}
}

func TestCan_WildcardAll(t *testing.T) {
	u := &pb.SessionUser{Permissions: []string{"*"}}
	if !Can(u, "anything.at.all") {
		t.Error("expected '*' to grant anything")
	}
}

func TestCan_NilUser(t *testing.T) {
	if Can(nil, "task.view") {
		t.Error("expected false for nil user")
	}
}
