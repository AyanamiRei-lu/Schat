package mobile

import (
	"encoding/json"
	"testing"
)

// 成员列表说的是不是真话。
//
// 这个函数唯一的价值是"谁在群里"这句话是真的。它从树的叶子里读签名密钥，所以测试必须比对
// 的是**那些身份本身**，而不是"数组非空"——一个把所有人读成同一个人的实现也能让"非空"通过。

func signingPublicOf(t *testing.T, identityJSON string) string {
	t.Helper()
	var raw struct {
		SigningPublic string `json:"signing_public"`
	}
	if err := json.Unmarshal([]byte(identityJSON), &raw); err != nil {
		t.Fatalf("the identity JSON has no signing_public: %v", err)
	}
	if raw.SigningPublic == "" {
		t.Fatal("the identity JSON has an empty signing_public")
	}
	return raw.SigningPublic
}

func TestGroupMembersListsEveryoneExactly(t *testing.T) {
	aliceIdentity, bobIdentity, aliceState, bobState := aliceAndState(t)

	alicePublic := signingPublicOf(t, aliceIdentity)
	bobPublic := signingPublicOf(t, bobIdentity)

	read := func(state, who string) []GroupMember {
		t.Helper()
		out, err := GroupMembersJSON(state)
		if err != nil {
			t.Fatalf("GroupMembersJSON for %s: %v", who, err)
		}
		var members []GroupMember
		if err := json.Unmarshal([]byte(out), &members); err != nil {
			t.Fatalf("the members JSON is not an array of members: %v", err)
		}
		return members
	}

	fromAlice := read(aliceState, "Alice")
	fromBob := read(bobState, "Bob")

	if len(fromAlice) != 2 {
		t.Fatalf("Alice sees %d members, want 2", len(fromAlice))
	}

	// 两位成员必须**互不相同**，且身份必须是那两个人的。
	seen := map[string]int64{}
	for _, m := range fromAlice {
		seen[m.Identity] = m.Leaf
	}
	if _, ok := seen[alicePublic]; !ok {
		t.Fatalf("Alice's own identity is not in the member list: %v", seen)
	}
	if _, ok := seen[bobPublic]; !ok {
		t.Fatalf("Bob's identity is not in the member list: %v", seen)
	}
	if seen[alicePublic] == seen[bobPublic] {
		t.Fatal("both members report the same leaf, so one of them is not really listed")
	}

	// 两个人看同一个群，必须看到同一份名单——叶子下标是群的属性，不是观察者的。
	if len(fromBob) != len(fromAlice) {
		t.Fatalf("Alice sees %d members and Bob sees %d", len(fromAlice), len(fromBob))
	}
	for i := range fromAlice {
		if fromAlice[i] != fromBob[i] {
			t.Fatalf("member %d differs between the two views: %+v against %+v",
				i, fromAlice[i], fromBob[i])
		}
	}

	// 顺序必须稳定：同一个状态读两次给出同一个顺序，界面才不会因为刷新而重排。
	again := read(aliceState, "Alice again")
	for i := range fromAlice {
		if fromAlice[i] != again[i] {
			t.Fatal("two reads of the same state gave different orders")
		}
	}
}

func TestGroupMembersRefusesNonsense(t *testing.T) {
	if _, err := GroupMembersJSON("not a state"); err == nil {
		t.Fatal("a member list was produced for something that is not a group state")
	}
	if _, err := GroupMembersJSON(""); err == nil {
		t.Fatal("a member list was produced for an empty state")
	}
}
