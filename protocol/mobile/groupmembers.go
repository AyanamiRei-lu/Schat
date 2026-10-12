package mobile

import (
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/schat/schat/protocol/mls/group"
)

// 群里有谁。
//
// # 为什么它需要一个导出函数
//
// 成员列表在树里，而树在加密快照里。客户端**不解析快照**——那一层是协议核心的职责——所以
// "谁在群里"必须由核心回答。界面拿到的是身份的十六进制，再与本机联系人对照得出备注名；
// 认不出的成员显示身份前缀，**绝不显示"未知"**：一个陌生的身份是一个事实，而"未知"不是。
//
// # 为什么返回 JSON 而不是切片
//
// gomobile 对结构体切片只有有限支持，而返回字符串是这一层已经在用的形状（发布资料、状态
// 摘要都是 JSON）。多一层 json.Marshal 换来的是"绑定层不会在切片上出意外"。
//
// # 身份用哪个字段
//
// 用叶子的**签名密钥**，不是凭证里的 identity：签名密钥是群里每个人用来验证消息的东西，
// 也是欢迎新成员时被写进树的东西。凭证里的 identity 是一个不被本实现使用的可选字段。

// GroupMember 是群里的一位成员。
type GroupMember struct {
	// Leaf 是它在该 epoch 的树里占的叶子下标。
	Leaf int64 `json:"leaf"`

	// Identity 是它的身份公钥（签名密钥）的十六进制。
	Identity string `json:"identity"`
}

// GroupMembersJSON 列出群里当前的成员，返回 JSON 数组。
//
// 顺序按叶子下标，因此同一棵树在两次调用里给出同一个顺序——界面不会因为刷新而重排。
func GroupMembersJSON(stateJSON string) (string, error) {
	epoch, err := group.RestoreEpoch([]byte(stateJSON))
	if err != nil {
		return "", err
	}

	members := make([]GroupMember, 0, len(epoch.Tree)/2)
	for node := 0; node < len(epoch.Tree); node += 2 {
		holder := epoch.Tree[node]
		if holder == nil || holder.Leaf == nil {
			// 空叶子是树长大时留下的空位，不是成员。
			continue
		}
		members = append(members, GroupMember{
			Leaf:     int64(node / 2),
			Identity: hex.EncodeToString(holder.Leaf.SignatureKey),
		})
	}

	out, err := json.Marshal(members)
	if err != nil {
		return "", fmt.Errorf("schat: listing the group's members: %w", err)
	}
	return string(out), nil
}
