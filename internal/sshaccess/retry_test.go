package sshaccess

import "testing"

func TestOpenRetryIsIdempotentButKeyCannotMoveObjectives(t *testing.T) {
	s, _, a, q, _ := fixture(t, false)
	one, e := s.Open(a, q)
	if e != nil {
		t.Fatal(e)
	}
	two, e := s.Open(a, q)
	if e != nil || one.ID != two.ID {
		t.Fatal("retry created second authorization")
	}
	q.ObjectiveID = "task-y"
	if _, e = s.Open(a, q); e == nil {
		t.Fatal("same key reused for new objective")
	}
}
