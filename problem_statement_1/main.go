package main

import (
    "fmt"
    "os"
    "strconv"

    "github.com/cilium/ebpf"
    "github.com/cilium/ebpf/rlimit"
)

const dropPortMapPath = "/sys/fs/bpf/tcp_drop_port_map"

func main() {
    // Raise the rlimit for BPF operations
    if err := rlimit.RemoveMemlock(); err != nil {
        fmt.Fprintf(os.Stderr, "failed to remove memlock: %v\n", err)
        os.Exit(1)
    }

    // Default port to drop
    port := uint32(4040)

    // Check if a port number is provided via command-line argument
    if len(os.Args) > 1 {
        p, err := strconv.Atoi(os.Args[1])
        if err != nil {
            fmt.Fprintf(os.Stderr, "invalid port number: %v\n", err)
            os.Exit(1)
        }
        port = uint32(p)
    }

    // Load the BPF map
    bpfMap, err := ebpf.LoadPinnedMap(dropPortMapPath, nil)
    if err != nil {
        fmt.Fprintf(os.Stderr, "failed to load BPF map: %v\n", err)
        os.Exit(1)
    }
    defer bpfMap.Close()

    // Key for the map entry
    var key uint32 = 0

    // Update the map with the new port number
    if err := bpfMap.Update(&key, &port, ebpf.UpdateAny); err != nil {
        fmt.Fprintf(os.Stderr, "failed to update BPF map: %v\n", err)
        os.Exit(1)
    }

    fmt.Printf("Successfully set the drop port to %d\n", port)
}
