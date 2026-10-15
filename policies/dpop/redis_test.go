/*
 * Copyright (c) 2026, WSO2 LLC. (https://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package dpop

import (
	"sync"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

// replicaWithRedis is one gateway replica: its own memory store, a shared Redis.
func replicaWithRedis(t *testing.T, mr *miniredis.Miniredis, failureMode string) *DPoPPolicy {
	t.Helper()
	p := newTestPolicy(t, nil)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr(), MaxRetries: -1})
	t.Cleanup(func() { _ = client.Close() })
	p.replay = &redisReplayStore{client: client, prefix: "dpop:v0:", failureMode: failureMode, local: newReplayStore(1000)}
	return p
}

func TestRedisReplayAcrossReplicas(t *testing.T) {
	mr := miniredis.RunT(t)
	a, b := replicaWithRedis(t, mr, redisFailureClosed), replicaWithRedis(t, mr, redisFailureClosed)
	key := newKey(t, "ES256")
	proof := key.sign(t, nil)
	expectAllowed(t, run(a, dpopRequest(key, proof)))
	// The same proof sent to another replica is a replay.
	expectRejected(t, run(b, dpopRequest(key, proof)), "invalid_dpop_proof")

	// Exactly one key, expiring with the proof (iat + proofMaxAge + clockSkew).
	keys := mr.Keys()
	if len(keys) != 1 {
		t.Fatalf("Redis holds %d keys, want 1", len(keys))
	}
	if ttl := mr.TTL(keys[0]); ttl <= 0 || ttl > 90*time.Second {
		t.Errorf("key TTL = %v, want (0, 90s]", ttl)
	}
	if keys[0][:len("dpop:v0:")] != "dpop:v0:" {
		t.Errorf("key %q lacks the prefix", keys[0])
	}
}

func TestRedisConcurrentReplayAcrossReplicas(t *testing.T) {
	mr := miniredis.RunT(t)
	replicas := []*DPoPPolicy{replicaWithRedis(t, mr, redisFailureClosed), replicaWithRedis(t, mr, redisFailureClosed), replicaWithRedis(t, mr, redisFailureClosed)}
	key := newKey(t, "ES256")
	proof := key.sign(t, nil)
	var wg sync.WaitGroup
	var mu sync.Mutex
	accepted := 0
	for i := 0; i < 30; i++ {
		wg.Add(1)
		go func(p *DPoPPolicy) {
			defer wg.Done()
			if _, ok := run(p, dpopRequest(key, proof)).(policy.UpstreamRequestHeaderModifications); ok {
				mu.Lock()
				accepted++
				mu.Unlock()
			}
		}(replicas[i%len(replicas)])
	}
	wg.Wait()
	if accepted != 1 {
		t.Fatalf("accepted %d copies of one proof across replicas, want 1", accepted)
	}
}

func TestRedisUnavailableFailsClosed(t *testing.T) {
	mr := miniredis.RunT(t)
	p := replicaWithRedis(t, mr, redisFailureClosed)
	mr.Close()
	key := newKey(t, "ES256")
	resp, ok := run(p, dpopRequest(key, key.sign(t, nil))).(policy.ImmediateResponse)
	if !ok || resp.StatusCode != 503 {
		t.Fatalf("Redis down, failureMode closed: got %+v, want 503", resp)
	}
}

func TestRedisUnavailableFallsBackToLocal(t *testing.T) {
	mr := miniredis.RunT(t)
	p := replicaWithRedis(t, mr, redisFailureLocal)
	mr.Close()
	key := newKey(t, "ES256")
	proof := key.sign(t, nil)
	expectAllowed(t, run(p, dpopRequest(key, proof)))
	// The replica's own store still refuses the replay.
	expectRejected(t, run(p, dpopRequest(key, proof)), "invalid_dpop_proof")
}

func TestRedisConfiguredThroughParams(t *testing.T) {
	mr := miniredis.RunT(t)
	params := map[string]interface{}{
		"replayStore": "redis",
		"redis":       map[string]interface{}{"host": mr.Host(), "port": float64(mr.Server().Addr().Port), "keyPrefix": "gw1:dpop:"},
	}
	pol, err := GetPolicy(policy.PolicyMetadata{}, params)
	if err != nil {
		t.Fatal(err)
	}
	p := pol.(*DPoPPolicy)
	p.now = func() time.Time { return testNow }
	key := newKey(t, "ES256")
	expectAllowed(t, run(p, dpopRequest(key, key.sign(t, nil))))
	if keys := mr.Keys(); len(keys) != 1 || keys[0][:9] != "gw1:dpop:" {
		t.Errorf("Redis keys = %v", keys)
	}
}

func TestRedisConfigValidation(t *testing.T) {
	bad := []map[string]interface{}{
		{"replayStore": "memcached"},
		{"replayStore": "redis", "redis": map[string]interface{}{"failureMode": "open"}},
		{"replayStore": "redis", "redis": map[string]interface{}{"port": float64(70000)}},
		{"replayStore": "redis", "redis": map[string]interface{}{"readTimeout": "fast"}},
		{"replayStore": "redis", "redis": map[string]interface{}{"tls": map[string]interface{}{"enabled": true, "certFile": "/x.pem"}}},
		{"replayStore": "redis", "redis": map[string]interface{}{"tls": map[string]interface{}{"enabled": true, "caFile": "/does/not/exist.pem"}}},
	}
	for _, params := range bad {
		if _, err := GetPolicy(policy.PolicyMetadata{}, params); err == nil {
			t.Errorf("GetPolicy accepted %v", params)
		}
	}
	if pol, err := GetPolicy(policy.PolicyMetadata{}, nil); err != nil {
		t.Fatal(err)
	} else if _, ok := pol.(*DPoPPolicy).replay.(*replayStore); !ok {
		t.Errorf("default replay store is %T, want memory", pol.(*DPoPPolicy).replay)
	}
}
