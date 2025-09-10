package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"

	"k8s.io/klog/v2"
)

// ----------------- 数据结构 -----------------

type persistData struct {
	CIDR      string   `json:"cidr"`
	Allocated []string `json:"allocated"`
	Last      uint32   `json:"last"`
}

type Allocator struct {
	cidr      *net.IPNet
	start     uint32
	end       uint32
	allocated map[uint32]struct{}
	last      uint32
	mu        sync.Mutex
	path      string
}

// ----------------- 分配器 -----------------

func NewAllocator(cidrStr string, persistPath string) (*Allocator, error) {
	ip, ipNet, err := net.ParseCIDR(cidrStr)
	if err != nil {
		return nil, err
	}
	if ip.To4() == nil {
		return nil, errors.New("只支持 IPv4")
	}

	start, end := cidrRange(ipNet)
	alloc := &Allocator{
		cidr:      ipNet,
		start:     start,
		end:       end,
		allocated: make(map[uint32]struct{}),
		last:      start,
		path:      persistPath,
	}
	if persistPath != "" {
		if err := alloc.load(); err != nil && !os.IsNotExist(err) {
			return nil, err
		}
	}
	return alloc, nil
}

func cidrRange(ipNet *net.IPNet) (uint32, uint32) {
	ip := ipNet.IP.To4()
	mask := net.IP(ipNet.Mask).To4()
	ipInt := ipToUint32(ip)
	maskInt := ipToUint32(mask)
	network := ipInt & maskInt
	broadcast := network | (^maskInt)

	if broadcast-network+1 <= 2 {
		return network, broadcast
	}
	return network + 1, broadcast - 1
}

func ipToUint32(ip net.IP) uint32 {
	b := ip.To4()
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}

func uint32ToIP(u uint32) net.IP {
	b := []byte{byte(u >> 24), byte(u >> 16), byte(u >> 8), byte(u)}
	return net.IPv4(b[0], b[1], b[2], b[3])
}

func (a *Allocator) Allocate() (net.IP, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if uint64(len(a.allocated)) >= uint64(a.end-a.start+1) {
		return nil, errors.New("no available IPs")
	}
	n := a.end - a.start + 1
	for i := uint32(0); i < n; i++ {
		idx := a.start + ((a.last - a.start + 1 + i) % n)
		if _, ok := a.allocated[idx]; !ok {
			a.allocated[idx] = struct{}{}
			a.last = idx
			ip := uint32ToIP(idx)
			_ = a.save()
			return ip, nil
		}
	}
	return nil, errors.New("no available IPs")
}

func (a *Allocator) Release(ip net.IP) error {
	if ip == nil || ip.To4() == nil {
		return errors.New("invalid ip")
	}
	u := ipToUint32(ip.To4())
	a.mu.Lock()
	defer a.mu.Unlock()
	if u < a.start || u > a.end {
		return errors.New("ip not in range")
	}
	if _, ok := a.allocated[u]; !ok {
		return errors.New("ip not allocated")
	}
	delete(a.allocated, u)
	return a.save()
}

func (a *Allocator) List() []net.IP {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := make([]net.IP, 0, len(a.allocated))
	for u := range a.allocated {
		out = append(out, uint32ToIP(u))
	}
	sort.Slice(out, func(i, j int) bool {
		return ipToUint32(out[i]) < ipToUint32(out[j])
	})
	return out
}

func (a *Allocator) save() error {
	if a.path == "" {
		return nil
	}
	pd := persistData{
		CIDR:      a.cidr.String(),
		Allocated: make([]string, 0, len(a.allocated)),
		Last:      a.last,
	}
	for u := range a.allocated {
		pd.Allocated = append(pd.Allocated, uint32ToIP(u).String())
	}
	sort.Strings(pd.Allocated)
	bs, err := json.MarshalIndent(pd, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(a.path, bs, 0644)
}

func (a *Allocator) load() error {
	if a.path == "" {
		return nil
	}
	bs, err := os.ReadFile(a.path)
	if err != nil {
		return err
	}
	var pd persistData
	if err := json.Unmarshal(bs, &pd); err != nil {
		return err
	}
	if pd.CIDR != a.cidr.String() {
		return fmt.Errorf("persist file CIDR mismatch: %s vs %s", pd.CIDR, a.cidr.String())
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.allocated = make(map[uint32]struct{})
	for _, s := range pd.Allocated {
		ip := net.ParseIP(s)
		if ip == nil || ip.To4() == nil {
			continue
		}
		u := ipToUint32(ip.To4())
		if u < a.start || u > a.end {
			continue
		}
		a.allocated[u] = struct{}{}
	}
	a.last = pd.Last
	if a.last < a.start || a.last > a.end {
		a.last = a.start
	}
	return nil
}

// ----------------- HTTP 服务 -----------------

var authToken string

func authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		klog.Infof("handle: %s", r.URL.Path)
		token := r.Header.Get("Authorization")
		if !strings.HasPrefix(token, "Bearer ") {
			http.Error(w, "missing or invalid token", http.StatusUnauthorized)
			return
		}
		provided := strings.TrimPrefix(token, "Bearer ")
		if provided != authToken {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func main() {
	cidr := os.Getenv("CIDR")
	if cidr == "" {
		cidr = "10.234.64.0/18"
	}
	path := os.Getenv("DATA_FILE")
	if path == "" {
		path = "./ip_alloc.json"
	}
	token := os.Getenv("AUTH_TOKEN")
	if token == "" {
		panic("AUTH_TOKEN must be set")
	}
	authToken = token

	alloc, err := NewAllocator(cidr, path)
	if err != nil {
		panic(err)
	}

	http.Handle("/allocate", authMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip, err := alloc.Allocate()
		if err != nil {
			w.WriteHeader(http.StatusConflict)
			fmt.Fprintln(w, err.Error())
			return
		}
		fmt.Fprintln(w, ip.String())
	})))

	http.Handle("/release", authMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ipStr := r.URL.Query().Get("ip")
		if ipStr == "" {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprintln(w, "missing ip")
			return
		}
		ip := net.ParseIP(ipStr)
		if err := alloc.Release(ip); err != nil {
			w.WriteHeader(http.StatusConflict)
			fmt.Fprintln(w, err.Error())
			return
		}
		fmt.Fprintln(w, "released")
	})))

	http.Handle("/list", authMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ips := alloc.List()
		for _, ip := range ips {
			fmt.Fprintln(w, ip.String())
		}
	})))

	http.Handle("/info", authMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		total := alloc.end - alloc.start + 1
		used := len(alloc.allocated)
		free := int(total) - used
		resp := map[string]interface{}{
			"cidr":  alloc.cidr.String(),
			"range": fmt.Sprintf("%s - %s", uint32ToIP(alloc.start), uint32ToIP(alloc.end)),
			"total": total,
			"used":  used,
			"free":  free,
		}
		_ = json.NewEncoder(w).Encode(resp)
	})))

	// 健康检查接口，无需鉴权
	http.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "ok")
	})

	addr := ":8080"
	if p := os.Getenv("PORT"); p != "" {
		addr = ":" + strings.TrimPrefix(p, ":")
	}
	fmt.Println("Starting IP allocator HTTP server on", addr)
	http.ListenAndServe(addr, nil)
}
